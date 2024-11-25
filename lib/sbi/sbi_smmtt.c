#include <sbi/sbi_smmtt.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_bitops.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_heap.h>
#include <sbi_utils/fdt/fdt_helper.h>
#include <libfdt.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_math.h>

// Macro for ensuring we don't overwrite a preset field with a new value
#define MTTL2_FIELD_ENSURE_EQUAL(entry, field, val)          \
	if (entry->field == 0) {            \
		entry->field = val;          \
	} else if (entry->field != val) { \
		return SBI_EINVAL;                               \
	}

#define ENSURE_ZERO(expr)          \
	if (expr != 0) {         \
		return SBI_EINVAL; \
	}

#define FITS(base, size, region) \
	((size >= region) && !(base % region))

static struct sbi_heap_control *smmtt_hpctrl = NULL;
static uint64_t smmtt_table_base, smmtt_table_size;

#define mttl3_size 1024 * 8
#define mttl2_size 0x200000 * 8

#define MiB (1ULL << 20)
#define GiB (1ULL << 30)

/* MTTP handling */

void mttp_set(smmtt_mode mode, unsigned int sdid, uintptr_t ppn)
{
	uintptr_t mttp  = INSERT_FIELD(0, MTTP_MODE_MASK, mode);
	mttp 			= INSERT_FIELD(mttp, MTTP_SDID_MASK, sdid);
	mttp 			= INSERT_FIELD(mttp, MTTP_PPN_MASK, ppn);
	csr_write(CSR_MTTP, mttp);
}

uintptr_t mttp_get()
{
	uintptr_t mttp = csr_read(CSR_MTTP);
	return mttp;
}

/* Internal decoding helpers */
static int get_mode_info(smmtt_mode mode, int *levels)
{
	*levels = -1;

	switch (mode)
	{
	case SMMTT_BARE:
		break;
#if __riscv_xlen == 32
	case SMMTT_34:
#elif __riscv_xlen == 64
	case SMMTT_46:
		*levels = 2;
		break;
	case SMMTT_56:
		*levels = 3;
		break;
#endif
	default:
		return SBI_EINVAL;
	}

	return SBI_OK;
}

/* SMMTT Updates */

static inline uint64_t mttl2_1g_type_from_flag(unsigned long flag) {
	if (flag & SBI_DOMAIN_MEMREGION_SU_READABLE) {
		if (flag & SBI_DOMAIN_MEMREGION_SU_WRITABLE) {
			return MTT_L2_1G_ALLOW_RWX;
		} else {
			return MTT_L2_1G_ALLOW_RX;
		}
	} else {
		return MTT_L2_1G_DISALLOW;
	}
}

static int smmtt_add_region_mttl2_1g(mttl2_entry *entry, unsigned long flag)
{
	// Ensure we're not trying to change the type of this mttl2 entry
	smmtt_type type = mttl2_1g_type_from_flag(flag);
	MTTL2_FIELD_ENSURE_EQUAL(entry, type, type);

	// Ensure info and zero fields are set to zero
	entry->info = 0;
	entry->zero = 0;
	return SBI_OK;
}

static inline mttl2_2m_pages mttl2_2m_perms_from_flag(unsigned long flag)
{
	if (flag & SBI_DOMAIN_MEMREGION_SU_READABLE) {
		if (flag & SBI_DOMAIN_MEMREGION_SU_WRITABLE) {
			return MTT_L2_2M_PAGES_ALLOW_RWX;
		} else {
			return MTT_L2_2M_PAGES_ALLOW_RX;
		}
	} else {
		return MTT_L2_2M_PAGES_DISALLOWED;
	}

}

static int smmtt_add_region_mttl2_2m(mttl2_entry *entry, unsigned long addr,
				     unsigned long flag)
{
	uintptr_t offset;
	uint32_t info, perms, field;
	smmtt_type type = MTT_L2_2M_PAGES;

	// Ensure we're not trying to change the type of this mttl2 entry
	MTTL2_FIELD_ENSURE_EQUAL(entry, type, type);

	// Determine offset in mttl2 entry that this address belongs to
	offset = EXTRACT_FIELD(addr, MTTL2_PERMS_MASK);

	// Generate the bitfield for the permissions and ensure it is not set
	field = 0b11 << (2 * (offset));
	info = entry->info;
	ENSURE_ZERO(EXTRACT_FIELD(entry->info, field));

	// Set the new permissions
	perms = mttl2_2m_perms_from_flag(flag);
	info = INSERT_FIELD(info, field, perms);
	entry->info = info;

	// Ensure zero field is zero
	entry->zero = 0;
	return SBI_OK;
}

static inline mttl1_entry *get_mttl1(mttl2_entry *entry)
{
	unsigned long ppn;
	mttl1_entry *mttl1 = NULL;

	// Make sure this entry is the correct type to have an mttl1
	if (entry->type != MTT_L2_MTT_L1_DIR) {
		return NULL;
	}

	if (entry->info) {
		// mttl1 already allocated, extract from mttl2
		ppn = entry->info;
		mttl1 = (mttl1_entry *)(ppn << PAGE_SHIFT);
	} else {
		// Allocate new mttl1
		mttl1 = sbi_aligned_alloc_from(smmtt_hpctrl, PAGE_SIZE, PAGE_SIZE);
		if (!mttl1) {
			return NULL;
		}

		// Link to mttl2
		entry->info = ((uintptr_t) mttl1) >> PAGE_SHIFT;

		// Ensure zero field is zero
		entry->zero = 0;
	}

	return mttl1;
}

static inline mttl1_perms mttl1_perms_from_flag(unsigned long flag)
{
	if (flag & SBI_DOMAIN_MEMREGION_SU_READABLE) {
		if (flag & SBI_DOMAIN_MEMREGION_SU_WRITABLE) {
			return MTT_L1_ALLOW_RWX;
		} else {
			return MTT_L1_ALLOW_RX;
		}
	} else {
		return MTT_L1_DISALLOWED;
	}
}

static int smmtt_add_region_mttl1(mttl2_entry *entry, unsigned long addr,
				  unsigned long flag)
{
	uintptr_t idx, offset;
	uint64_t field;
	mttl1_perms perms;
	mttl1_entry *mttl1;

	// Ensure we're not trying to change the type of this mttl2 entry
	MTTL2_FIELD_ENSURE_EQUAL(entry, type, MTT_L2_MTT_L1_DIR);

	// Allocate or get an existing mttl1 table
	mttl1 = get_mttl1(entry);
	if (!mttl1) {
		// Failed to allocate, reset entry
		entry->info = 0;
		entry->type = 0;
		entry->zero = 0;
		return SBI_ENOMEM;
	}

	// Determine index and offset in mttl1 that this address belongs to
	idx = EXTRACT_FIELD(addr, MTTL1_INDEX_MASK);
	offset = EXTRACT_FIELD(addr, MTTL1_OFFSET_MASK);

	// Generate the bitfield for the permissions and ensure it is not set
	field = 0b1111 << (4 * (offset));
	ENSURE_ZERO(EXTRACT_FIELD(mttl1[idx], field));

	// Set the new permissions
	perms = mttl1_perms_from_flag(flag);
	mttl1[idx] = INSERT_FIELD(mttl1[idx], field, perms);
	return SBI_OK;
}


static int smmtt_add_region_mttl2(mttl2_entry *l2_table, unsigned long addr,
				  unsigned long size, unsigned long flag)
{
	int rc, i;
	uintptr_t idx;
	mttl2_entry *entry;

	while (size != 0) {
		idx = EXTRACT_FIELD(addr, MTTL2_INDEX_MASK);
		entry = &l2_table[idx];
		entry->zero = 0;

		if (FITS(addr, size, GiB)) {
			for (i = 0; i < 32; i++) {
				rc = smmtt_add_region_mttl2_1g(entry + i, flag);
				if (rc < 0) {
					return rc;
				}
			}

			size -= GiB;
			addr += GiB;
		} else if (FITS(addr, size, (2 * MiB))) {
			rc = smmtt_add_region_mttl2_2m(entry, addr, flag);
			if (rc < 0) {
				return rc;
			}

			size -= (2 * MiB);
			addr += (2 * MiB);
		} else {
			rc = smmtt_add_region_mttl1(entry, addr, flag);
			if (rc < 0) {
				return rc;
			}

			size -= PAGE_SIZE;
			addr += PAGE_SIZE;
		}
	}

	return SBI_OK;
}

#if __riscv_xlen == 64
static int smmtt_add_region_mttl3(mttl3_entry *l3_table, unsigned long addr,
				  unsigned long size, unsigned long flag)
{
	unsigned long ppn;
	mttl2_entry *mttl2;
	uintptr_t idx = EXTRACT_FIELD(addr, MTTL3_INDEX_MASK);

	if (l3_table[idx].ppn == 0) {
		mttl2 = sbi_aligned_alloc_from(smmtt_hpctrl, mttl2_size, mttl2_size);
		ppn = ((uintptr_t)mttl2) >> PAGE_SHIFT;
		l3_table[idx].ppn = ppn;
		l3_table[idx].zero	= 0;
	} else {
		ppn = l3_table[idx].ppn;
		mttl2 = (mttl2_entry *)(ppn << PAGE_SHIFT);
	}

	if (!mttl2) {
		return SBI_ENOMEM;
	}

	return smmtt_add_region_mttl2(mttl2, addr, size, flag);
}
#endif

/* External interfaces */

static int initialize_mtt(struct sbi_domain *dom, struct sbi_scratch *scratch)
{
	int rc, levels, size;
	struct sbi_domain_memregion *reg;

	if (!dom->mtt) {
		// Assign the default SMMTT mode if this domain does not
		// have a specified one yet
		if (dom->smmtt_mode == SMMTT_BARE) {
			dom->smmtt_mode = SMMTT_46;
		}

		if (!sbi_hart_has_smmtt_mode(scratch, dom->smmtt_mode)) {
			return SBI_EINVAL;
		}

		// Allocate an appropriately sized MTT
		rc = get_mode_info(dom->smmtt_mode, &levels);
		if (rc < 0) {
			return rc;
		}

#if __riscv_xlen == 64
		if (levels == 3) {
			dom->mtt = sbi_aligned_alloc_from(smmtt_hpctrl,
							  mttl3_size, mttl3_size);
		}
#endif
		if (levels == 2) {
			dom->mtt = sbi_aligned_alloc_from(smmtt_hpctrl,
							  mttl2_size, mttl2_size);
		}

		if (!dom->mtt) {
			return SBI_ENOMEM;
		}

		sbi_domain_for_each_memregion(dom, reg)
		{
			if (!(reg->flags & SBI_DOMAIN_MEMREGION_SU_RWX)) {
				continue;
			}
            size = 2 ^ (reg->order);
#if __riscv_xlen == 64
			if (levels == 3) {
				smmtt_add_region_mttl3(dom->mtt, reg->base,
						       size, reg->flags);
			}
#endif

			if (levels == 2) {
				smmtt_add_region_mttl2(dom->mtt, reg->base,
						       size, reg->flags);
			}
		}
	}

	return SBI_OK;
}

int sbi_hart_smmtt_configure(struct sbi_scratch *scratch)
{
	int rc;
	unsigned int pmp_count;
	struct sbi_domain *dom = sbi_domain_thishart_ptr();

	rc = sbi_memregion_sanitize(dom, SBI_ISOLATION_SMMTT);
	if (rc < 0) {
		return rc;
	}

	/* Ensure table is rendered */
	rc = initialize_mtt(dom, scratch);
	if (rc < 0) {
		return rc;
	}

	/* Install table and PMP */

	// For PMP, we allow access to everything except for the SMMTT
	// tables (disabled by highest priority register).
	pmp_count = sbi_hart_pmp_count(scratch);
	pmp_set(pmp_count - 1, PMP_R | PMP_W | PMP_X, 0, __riscv_xlen);
	pmp_set(0, 0, smmtt_table_base, log2roundup(smmtt_table_size));

	// For SMMTT, we only selectively enable access as specified
	// by the domain configuration
	mttp_set(dom->smmtt_mode, 0, ((uintptr_t)dom->mtt) >> PAGE_SHIFT);

	// Both PMP and SMMTT checks apply for each access, and the final
	// permissions are the logical and of the two checks. Therefore,
	// unprivileged code can definitely never access the SMMTT tables
	// because of the PMP configuration. Unprivileged code can also not
	// access anything besides what SMMTT explicitly enables.

	return 0;
}
