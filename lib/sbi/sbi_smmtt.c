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
#include <sbi/smmtt_defs.h>
#include <sbi/sbi_domain.h>

/* Globals */
static struct sbi_heap_control *smmtt_hpctrl = NULL;

static uint64_t smmtt_table_base, smmtt_table_size;

/* Definitions */

#if __riscv_xlen == 32
#define SMMTT_DEFAULT_MODE (SMMTT_34)
#define MTTL2_SIZE (0x4 * 0x400)
#else
#define SMMTT_DEFAULT_MODE (SMMTT_46)
#define MTTL3_SIZE (0x8 * 0x400)
#define MTTL2_SIZE (0x10 * 0x400 * 0x400)
#endif

#define ENSURE_EQUAL(expr, val)       \
	if ((expr) == 0) {            \
		(expr) = (val);       \
	} else if ((expr) != (val)) { \
		return SBI_EINVAL;    \
	}
#define ENSURE_ZERO(expr)          \
	if ((expr) != 0) {         \
		return SBI_EINVAL; \
	}

#define MTTL2_FIELD_ENSURE_EQUAL(entry, field, val)          \
	if ((entry)->field == 0) {            \
		(entry)->field = val;          \
	} else if ((entry)->field != (val)) { \
		return SBI_EINVAL;                               \
	}

/* MTTP handling */

unsigned int mttp_get_sdidlen()
{
	smmtt_mode_t mode;
	unsigned int sdid, sdidlen;
	uintptr_t ppn;
	// Save current values in mttp
	mttp_get(&mode, &sdid, &ppn);
	// Write all ones to SDID and get values back
	mttp_set(SMMTT_BARE, (unsigned int)-1, 0);
	mttp_get(NULL, &sdidlen, NULL);
	// Reset back old values
	mttp_set(mode, sdid, ppn);
	if (sdidlen == 0) {
		return 0;
	} else {
		return sbi_fls(sdidlen) + 1;
	}
}
void mttp_set(smmtt_mode_t mode, unsigned int sdid, uintptr_t ppn)
{
	uintptr_t mttp = INSERT_FIELD(0, MTTP_PPN, ppn);
	mttp	       = INSERT_FIELD(mttp, MTTP_SDID, sdid);
	mttp	       = INSERT_FIELD(mttp, MTTP_MODE, mode);
	csr_write(CSR_MTTP, mttp);
}

void mttp_get(smmtt_mode_t *mode, unsigned int *sdid, uintptr_t *ppn)
{
	uintptr_t mttp = csr_read(CSR_MTTP);
	if(mode) {
		*mode = (mttp & MTTP_MODE) >> MTTP_MODE_SHIFT;
	}
	if(sdid) {
		*sdid = (mttp & MTTP_SDID) >> MTTP_SDID_SHIFT;
	}
	if(ppn) {
		*ppn = (mttp & MTTP_PPN);
	}
}

/* Internal decoding helpers */

static int get_smmtt_mode_info(smmtt_mode_t mode, int *levels)
{
	int olevels = -1;

	switch (mode) {
	case SMMTT_BARE:
		olevels = -1;
		break;

#if __riscv_xlen == 32
	// fall through
	case SMMTT_34:
#elif __riscv_xlen == 64
	// fall through
	case SMMTT_46:
#endif
		olevels = 2;
		break;

#if __riscv_xlen == 64
	case SMMTT_56:
		olevels = 3;
		break;
#endif
	default:
		return SBI_EINVAL;
	}

	if (levels) {
		*levels = olevels;
	}

	return SBI_OK;
}

/* SMMTT Updates */

static inline mttl1_entry *mttl1_from_mttl2(mttl2_entry *entry)
{
	unsigned long mttl1_ppn;
	mttl1_entry *mttl1 = NULL;

	// Make sure this entry is the correct type to have an mttl1
	if (entry->type != SMMTT_TYPE_MTT_L1_DIR) {
		return NULL;
	}

	if (entry->info) {
		// mttl1 already allocated, extract from mttl2
		mttl1_ppn = entry->info;
		mttl1 = (mttl1_entry *)(mttl1_ppn << PAGE_SHIFT);
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

static inline smmtt_perms_mtt_l1_dir mttl1_perms_from_flags(unsigned long flags)
{
	if (flags & SBI_DOMAIN_MEMREGION_SU_READABLE) {
		if (flags & SBI_DOMAIN_MEMREGION_SU_WRITABLE) {
			if (flags & SBI_DOMAIN_MEMREGION_SU_EXECUTABLE) {
				return SMMTT_PERMS_MTT_L1_DIR_ALLOW_RWX;
			} else {
				return SMMTT_PERMS_MTT_L1_DIR_ALLOW_RW;
			}
		} else {
			if (flags & SBI_DOMAIN_MEMREGION_SU_EXECUTABLE) {
				return SMMTT_PERMS_MTT_L1_DIR_ALLOW_RX;
			} else {
				/* Cannot encode readonly */
				return SMMTT_PERMS_MTT_L1_DIR_DISALLOWED;
			}
		}
	} else {
		return SMMTT_PERMS_MTT_L1_DIR_DISALLOWED;
	}
}

static int smmtt_add_region_mttl1(mttl2_entry *entry, unsigned long addr,
				  unsigned long flags)
{
	uintptr_t idx, offset;
	uint64_t field;
	smmtt_perms_mtt_l1_dir perms;
	mttl1_entry *mttl1;

	// Ensure we're not trying to change the type of this mttl2 entry
	MTTL2_FIELD_ENSURE_EQUAL(entry, type, SMMTT_TYPE_MTT_L1_DIR);

	// Allocate or get an existing mttl1 table
	mttl1 = mttl1_from_mttl2(entry);
	if (!mttl1) {
		// Failed to allocate, reset entry
		entry->info = 0;
		entry->type = 0;
		entry->zero = 0;
		return SBI_ENOMEM;
	}

	// Determine index and offset in mttl1 that this address belongs to
	idx = EXTRACT_FIELD(addr, SPA_PN1);
	offset = EXTRACT_FIELD(addr, SPA_PN0);

	// Generate the bitfield for the permissions and ensure it is not set
	field = MTT_PERM_FIELD(offset);
	ENSURE_ZERO(EXTRACT_FIELD(mttl1[idx], field));

	// Set the new permissions
	perms = mttl1_perms_from_flags(flags);
	mttl1[idx] = INSERT_FIELD(mttl1[idx], field, perms);
	return SBI_OK;
}

static inline smmtt_perms_xm_pages mttl2_xm_perms_from_flags(unsigned long flags)
{
	if (flags & SBI_DOMAIN_MEMREGION_SU_READABLE) {
		if (flags & SBI_DOMAIN_MEMREGION_SU_WRITABLE) {
			if (flags & SBI_DOMAIN_MEMREGION_SU_EXECUTABLE) {
				return SMMTT_PERMS_XM_PAGES_ALLOW_RWX;
			} else {
				return SMMTT_PERMS_XM_PAGES_ALLOW_RW;
			}
		} else {
			if (flags & SBI_DOMAIN_MEMREGION_SU_EXECUTABLE) {
				return SMMTT_PERMS_XM_PAGES_ALLOW_RX;
			} else {
				/* Cannot encode readonly */
				return SMMTT_PERMS_XM_PAGES_DISALLOWED;
			}
		}
	} else {
		return SMMTT_PERMS_XM_PAGES_DISALLOWED;
	}
}
static int smmtt_add_region_mttl2_xm(mttl2_entry *entry, unsigned long addr,
				     unsigned long flags)
{
	uintptr_t offset;
	uint32_t info, perms, field;
#if __riscv_xlen == 32
	smmtt_type type = SMMTT_TYPE_4M_PAGES;
#else
	smmtt_type type = SMMTT_TYPE_2M_PAGES;
#endif

	// Ensure we're not trying to change the type of this mttl2 entry
	MTTL2_FIELD_ENSURE_EQUAL(entry, type, type);

	// Determine offset in mttl2 entry that this address belongs to
	offset = EXTRACT_FIELD(addr, SPA_XM_OFFS);

	// Generate the bitfield for the permissions and ensure it is not set
	field = MTT_PERM_FIELD(offset);
	info = entry->info;
	ENSURE_ZERO(EXTRACT_FIELD(entry->info, field));

	// Set the new permissions
	perms = mttl2_xm_perms_from_flags(flags);
	info = INSERT_FIELD(info, field, perms);
	entry->info = info;

	// Ensure zero field is zero
	entry->zero = 0;
	return SBI_OK;
}

static inline uint64_t mttl2_1g_type_from_flags(unsigned long flags) {
	if (flags & SBI_DOMAIN_MEMREGION_SU_READABLE) {
		if (flags & SBI_DOMAIN_MEMREGION_SU_WRITABLE) {
			if (flags & SBI_DOMAIN_MEMREGION_SU_EXECUTABLE) {
				return SMMTT_TYPE_1G_ALLOW_RWX;
			} else {
				return SMMTT_TYPE_1G_ALLOW_RW;
			}
		} else {
			if (flags & SBI_DOMAIN_MEMREGION_SU_EXECUTABLE) {
				return SMMTT_TYPE_1G_ALLOW_RX;
			} else {
				/* Cannot encode readonly */
				return SMMTT_TYPE_1G_DISALLOW;
			}
		}
	} else {
		return SMMTT_TYPE_1G_DISALLOW;
	}
}

static int smmtt_add_region_mttl2_1g(mttl2_entry *entry, unsigned long flags)
{
	// Ensure we're not trying to change the type of this mttl2 entry
	smmtt_type type = mttl2_1g_type_from_flags(flags);
	MTTL2_FIELD_ENSURE_EQUAL(entry, type, type);

	// Ensure info and zero fields are set to zero
	entry->info = 0;
	entry->zero = 0;
	return SBI_OK;
}

#define FITS(base, size, region) \
	(((size) >= (region)) && (!((base) % (region))))

#define MiB (1UL << 20)
#define GiB (1ULL << 30)

#if __riscv_xlen == 32
#define XM_SIZE (4 * MiB)
#else
#define XM_SIZE (2 * MiB)
#endif

static int smmtt_add_region_mttl2(mttl2_entry *mttl2, unsigned long base,
				  unsigned long size, unsigned long flags)
{
	int rc, i;
	uintptr_t idx;
	mttl2_entry *entry;

	while (size != 0) {
		idx = EXTRACT_FIELD(base, SPA_PN2);
		entry = &mttl2[idx];
		entry->zero = 0;

		if (FITS(base, size, GiB)) {
			for (i = 0; i < 32; i++) {
				rc = smmtt_add_region_mttl2_1g(&mttl2[idx + i], flags);
				if (rc < 0) {
					return rc;
				}
			}

			size -= GiB;
			base += GiB;
		} else if (FITS(base, size, XM_SIZE)) {
			rc = smmtt_add_region_mttl2_xm(entry, base, flags);
			if (rc < 0) {
				return rc;
			}

			size -= (XM_SIZE);
			base += (XM_SIZE);
		} else {
			rc = smmtt_add_region_mttl1(entry, base, flags);
			if (rc < 0) {
				return rc;
			}

			size -= PAGE_SIZE;
			base += PAGE_SIZE;
		}
	}

	return SBI_OK;
}

#if __riscv_xlen == 64
static int smmtt_add_region_mttl3(mttl3_entry *mttl3, unsigned long base,
				  unsigned long size, unsigned long flags)
{
	unsigned long mttl2_ppn;
	mttl2_entry *mttl2;
	uintptr_t idx = EXTRACT_FIELD(base, SPA_PN3);

	if (mttl3[idx].mttl2_ppn == 0) {
		mttl2 = sbi_aligned_alloc_from(smmtt_hpctrl, MTTL2_SIZE, MTTL2_SIZE);
		mttl2_ppn = ((uintptr_t)mttl2) >> PAGE_SHIFT;
		mttl3[idx].mttl2_ppn = mttl2_ppn;
		mttl3[idx].zero	= 0;
	} else {
		mttl2_ppn = mttl3[idx].mttl2_ppn;
		mttl2 = (mttl2_entry *)(mttl2_ppn << PAGE_SHIFT);
	}

	if (!mttl2) {
		return SBI_ENOMEM;
	}

	return smmtt_add_region_mttl2(mttl2, base, size, flags);
}
#endif

/* External interfaces */

static int initialize_mtt(struct sbi_domain *dom, struct sbi_scratch *scratch)
{
	int rc, levels;
	struct sbi_domain_memregion *reg;

	if (!dom->mtt) {
		// Assign the default SMMTT mode if this domain does not
		// have a specified one yet
		if (dom->smmtt_mode == SMMTT_BARE) {
			dom->smmtt_mode = SMMTT_DEFAULT_MODE;
		}

		if (!sbi_hart_has_smmtt_mode(scratch, dom->smmtt_mode)) {
			return SBI_EINVAL;
		}

		// Allocate an appropriately sized MTT
		rc = get_smmtt_mode_info(dom->smmtt_mode, &levels);
		if (rc < 0) {
			return rc;
		}

#if __riscv_xlen == 64
		if (levels == 3) {
			dom->mtt = sbi_aligned_alloc_from(smmtt_hpctrl,
							  MTTL3_SIZE, MTTL3_SIZE);
		}
#endif
		if (levels == 2) {
			dom->mtt = sbi_aligned_alloc_from(smmtt_hpctrl,
							  MTTL2_SIZE, MTTL2_SIZE);
		}

		if (!dom->mtt) {
			return SBI_ENOMEM;
		}

		sbi_domain_for_each_memregion(dom, reg)
		{
			if (!(reg->flags & SBI_DOMAIN_MEMREGION_SU_RWX)) {
				continue;
			}

#if __riscv_xlen == 64
			if (levels == 3) {
				smmtt_add_region_mttl3(dom->mtt, reg->base,
						       reg->size, reg->flags);
			}
#endif

			if (levels == 2) {
				smmtt_add_region_mttl2(dom->mtt, reg->base,
						       reg->size, reg->flags);
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

	rc = sbi_domain_memregions_sanitize(dom, SBI_ISOLATION_SMMTT);
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

static int setup_table_memory()
{
	const void *fdt;
	int namelen, ret;
	int reserved_node, table_node;
	const char *name;

	// Look for the smmtt_tables reserved memory node
	fdt	      = fdt_get_address();
	reserved_node = fdt_path_offset(fdt, "/reserved-memory");
	if (reserved_node < 0) {
		return SBI_ENOMEM;
	}

	fdt_for_each_subnode(table_node, fdt, reserved_node)
	{
		name = fdt_get_name(fdt, table_node, &namelen);
		if (name) {
			namelen = strlen("smmtt_tables");
			if (strncmp(name, "smmtt_tables", namelen) == 0) {
				break;
			}
		}
	}

	if (table_node == -FDT_ERR_NOTFOUND) {
		return SBI_ENOMEM;
	}

	// Extract base and size
	ret = fdt_get_node_addr_size(fdt, table_node, 0, &smmtt_table_base,
				     &smmtt_table_size);
	if (ret < 0) {
		return ret;
	}

	// Ensure NAPOT so we can later fit this in a single PMP register
	if ((smmtt_table_size & (smmtt_table_size - 1)) != 0) {
		return SBI_EINVAL;
	}

	if ((smmtt_table_base & (smmtt_table_size - 1)) != 0) {
		return SBI_EINVAL;
	}

	// Initialize the SMMTT table heap
	sbi_heap_alloc_new(&smmtt_hpctrl);
	sbi_heap_init_new(smmtt_hpctrl, smmtt_table_base, smmtt_table_size);

	return SBI_OK;
}

#define SECURE_DEVICE(status, sstatus) \
	(!strcmp(status, "disabled") && !strcmp(sstatus, "okay"))

#define NONSECURE_DEVICE(status, sstatus) \
	(!strcmp(status, "okay") && !strcmp(sstatus, "disabled"))

#define DISABLED_DEVICE(status, sstatus) \
	(!strcmp(status, "disabled") && !strcmp(sstatus, "disabled"))

#define AVAILABLE_DEVICE(status, sstatus) \
	(!strcmp(status, "okay") && !strcmp(sstatus, "okay"))

static int device_get_flags(const void *fdt, int dev, unsigned long *flags)
{
	const char *status, *sstatus, *name;

	status = fdt_getprop(fdt, dev, "status", NULL);
	if (!status)
		status = "okay";

	sstatus = fdt_getprop(fdt, dev, "secure-status", NULL);
	if (!sstatus)
		sstatus = status;

	*flags = SBI_DOMAIN_MEMREGION_MMIO;

	if (SECURE_DEVICE(status, sstatus) ||
	    DISABLED_DEVICE(status, sstatus)) {
		*flags |= (SBI_DOMAIN_MEMREGION_M_READABLE |
			  SBI_DOMAIN_MEMREGION_M_WRITABLE);
	} else if (NONSECURE_DEVICE(status, sstatus)) {
		*flags |= (SBI_DOMAIN_MEMREGION_SU_READABLE |
			  SBI_DOMAIN_MEMREGION_SU_WRITABLE);
	} else if (AVAILABLE_DEVICE(status, sstatus)) {
		*flags |= (SBI_DOMAIN_MEMREGION_M_READABLE |
			  SBI_DOMAIN_MEMREGION_M_WRITABLE |
			  SBI_DOMAIN_MEMREGION_SU_READABLE |
			  SBI_DOMAIN_MEMREGION_SU_WRITABLE);
	} else {
		name = fdt_get_name(fdt, dev, NULL);
		if (name) {
			sbi_printf("%s: invalid security specification "
				   "for device %s\n", __func__ , name);
		} else {
			sbi_printf("%s: invalid security specification\n",
				   __func__);
		}

		return SBI_EINVAL;
	}

	return SBI_OK;
}

static int create_regions_for_devices()
{
	int soc, dev, ret, i;
	uint64_t base, size;
	unsigned long flags;

	struct sbi_domain_memregion reg;

	const void *fdt = fdt_get_address();
	soc = fdt_path_offset(fdt, "/soc");
	if (soc < 0) {
		return SBI_EINVAL;
	}

	fdt_for_each_subnode(dev, fdt, soc) {
		// Find all devices with MMIO ranges
		if (fdt_get_property(fdt, dev, "reg", NULL)) {
			// Find permissions
			ret = device_get_flags(fdt, dev, &flags);
			if (ret < 0) {
				return ret;
			}

			i = 0;
			while(1) {
				ret = fdt_get_node_addr_size(fdt, dev, i++,
							     &base, &size);
				if (ret < 0) {
					break;
				}

				sbi_domain_memregion_init(base, size, flags, &reg);
				ret = sbi_domain_root_add_memregion(&reg);
				if(ret < 0) {
					return ret;
				}
			}
		}
	}

	return 0;
}

int sbi_smmtt_init(struct sbi_scratch *scratch, bool cold_boot)
{
	int rc;
	if (!sbi_hart_has_extension(scratch, SBI_HART_EXT_SMMTT)) {
		// Nothing to do
		return SBI_OK;
	}

	if (cold_boot) {
		rc = setup_table_memory();
		if (rc < 0)
			return rc;

		rc = create_regions_for_devices();
		if (rc < 0)
			return rc;
	}

	return SBI_OK;
}