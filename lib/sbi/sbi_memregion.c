#include <sbi/sbi_memregion.h>
#include <sbi/sbi_math.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_string.h>

void sbi_domain_memregion_init(unsigned long addr,
				unsigned long size,
				unsigned long flags,
				struct sbi_domain_memregion *reg)
{
	unsigned long base = 0, order;

	for (order = log2roundup(size) ; order <= __riscv_xlen; order++) {
		if (order < __riscv_xlen) {
			base = addr & ~((1UL << order) - 1UL);
			if ((base <= addr) &&
			    (addr < (base + (1UL << order))) &&
			    (base <= (addr + size - 1UL)) &&
			    ((addr + size - 1UL) < (base + (1UL << order))))
				break;
		} else {
			base = 0;
			break;
		}

	}

	if (reg) {
		reg->base = base;
		reg->order = order;
		reg->flags = flags;
	}
}


bool sbi_domain_check_addr(const struct sbi_domain *dom,
			   unsigned long addr, unsigned long mode,
			   unsigned long access_flags)
{
	bool rmmio, mmio = false;
	struct sbi_domain_memregion *reg;
	unsigned long rstart, rend, rflags, rwx = 0, rrwx = 0;

	if (!dom)
		return false;

	/*
	 * Use M_{R/W/X} bits because the SU-bits are at the
	 * same relative offsets. If the mode is not M, the SU
	 * bits will fall at same offsets after the shift.
	 */
	if (access_flags & SBI_DOMAIN_READ)
		rwx |= SBI_DOMAIN_MEMREGION_M_READABLE;

	if (access_flags & SBI_DOMAIN_WRITE)
		rwx |= SBI_DOMAIN_MEMREGION_M_WRITABLE;

	if (access_flags & SBI_DOMAIN_EXECUTE)
		rwx |= SBI_DOMAIN_MEMREGION_M_EXECUTABLE;

	if (access_flags & SBI_DOMAIN_MMIO)
		mmio = true;

	sbi_domain_for_each_memregion(dom, reg) {
		rflags = reg->flags;
		rrwx = (mode == PRV_M ?
			(rflags & SBI_DOMAIN_MEMREGION_M_ACCESS_MASK) :
			(rflags & SBI_DOMAIN_MEMREGION_SU_ACCESS_MASK)
			>> SBI_DOMAIN_MEMREGION_SU_ACCESS_SHIFT);

		rstart = reg->base;
		rend = (reg->order < __riscv_xlen) ?
			rstart + ((1UL << reg->order) - 1) : -1UL;
		if (rstart <= addr && addr <= rend) {
			rmmio = (rflags & SBI_DOMAIN_MEMREGION_MMIO) ? true : false;
			if (mmio != rmmio)
				return false;
			return ((rrwx & rwx) == rwx) ? true : false;
		}
	}

	return (mode == PRV_M) ? true : false;
}


/* Check if region complies with constraints */
static bool is_region_valid(const struct sbi_domain_memregion *reg)
{
	if (reg->order < 3 || __riscv_xlen < reg->order)
		return false;

	if (reg->order == __riscv_xlen && reg->base != 0)
		return false;

	if (reg->order < __riscv_xlen && (reg->base & (BIT(reg->order) - 1)))
		return false;

	return true;
}

/** Check if regionA is sub-region of regionB */
static bool is_region_subset(const struct sbi_domain_memregion *regA,
			     const struct sbi_domain_memregion *regB)
{
	ulong regA_start = regA->base;
	ulong regA_end = regA->base + (BIT(regA->order) - 1);
	ulong regB_start = regB->base;
	ulong regB_end = regB->base + (BIT(regB->order) - 1);

	if ((regB_start <= regA_start) &&
	    (regA_start < regB_end) &&
	    (regB_start < regA_end) &&
	    (regA_end <= regB_end))
		return true;

	return false;
}

/** Check if regionA can be replaced by regionB */
static bool is_region_compatible(const struct sbi_domain_memregion *regA,
				 const struct sbi_domain_memregion *regB)
{
	if (is_region_subset(regA, regB) && regA->flags == regB->flags)
		return true;

	return false;
}

/** Check if regionA should be placed before regionB */
static bool is_region_before(const struct sbi_domain_memregion *regA,
			     const struct sbi_domain_memregion *regB)
{
	if (regA->order < regB->order)
		return true;

	if ((regA->order == regB->order) &&
	    (regA->base < regB->base))
		return true;

	return false;
}

static const struct sbi_domain_memregion *find_region(
						const struct sbi_domain *dom,
						unsigned long addr)
{
	unsigned long rstart, rend;
	struct sbi_domain_memregion *reg;

	sbi_domain_for_each_memregion(dom, reg) {
		rstart = reg->base;
		rend = (reg->order < __riscv_xlen) ?
			rstart + ((1UL << reg->order) - 1) : -1UL;
		if (rstart <= addr && addr <= rend)
			return reg;
	}

	return NULL;
}

static const struct sbi_domain_memregion *find_next_subset_region(
				const struct sbi_domain *dom,
				const struct sbi_domain_memregion *reg,
				unsigned long addr)
{
	struct sbi_domain_memregion *sreg, *ret = NULL;

	sbi_domain_for_each_memregion(dom, sreg) {
		if (sreg == reg || (sreg->base <= addr) ||
		    !is_region_subset(sreg, reg))
			continue;

		if (!ret || (sreg->base < ret->base) ||
		    ((sreg->base == ret->base) && (sreg->order < ret->order)))
			ret = sreg;
	}

	return ret;
}

static void swap_region(struct sbi_domain_memregion* reg1,
			struct sbi_domain_memregion* reg2)
{
	struct sbi_domain_memregion treg;

	sbi_memcpy(&treg, reg1, sizeof(treg));
	sbi_memcpy(reg1, reg2, sizeof(treg));
	sbi_memcpy(reg2, &treg, sizeof(treg));
}

static void clear_region(struct sbi_domain_memregion* reg)
{
	sbi_memset(reg, 0x0, sizeof(*reg));
}

bool sbi_domain_check_addr_range(const struct sbi_domain *dom,
				 unsigned long addr, unsigned long size,
				 unsigned long mode,
				 unsigned long access_flags)
{
	unsigned long max = addr + size;
	const struct sbi_domain_memregion *reg, *sreg;

	if (!dom)
		return false;

	while (addr < max) {
		reg = find_region(dom, addr);
		if (!reg)
			return false;

		if (!sbi_domain_check_addr(dom, addr, mode, access_flags))
			return false;

		sreg = find_next_subset_region(dom, reg, addr);
		if (sreg)
			addr = sreg->base;
		else if (reg->order < __riscv_xlen)
			addr = reg->base + (1UL << reg->order);
		else
			break;
	}

	return true;
}

int sbi_domain_memregions_sanitize(struct sbi_domain *dom)
{
	u32 i, j, count;
    bool is_covered;
    struct sbi_domain_memregion *reg, *reg1;

    /* Check memory regions */
	if (!dom->regions) {
		sbi_printf("%s: %s regions is NULL\n",
			   __func__, dom->name);
		return SBI_EINVAL;
	}
	sbi_domain_for_each_memregion(dom, reg) {
		if (!is_region_valid(reg)) {
			sbi_printf("%s: %s has invalid region base=0x%lx "
				   "order=%lu flags=0x%lx\n", __func__,
				   dom->name, reg->base, reg->order,
				   reg->flags);
			return SBI_EINVAL;
		}
	}

	/* Count memory regions */
	count = 0;
	sbi_domain_for_each_memregion(dom, reg)
		count++;


	/* Check presence of firmware regions */
	if (!dom->fw_region_inited) {
		sbi_printf("%s: %s does not have firmware region\n",
			   __func__, dom->name);
		return SBI_EINVAL;
	}

	/* Sort the memory regions */
	for (i = 0; i < (count - 1); i++) {
		reg = &dom->regions[i];
		for (j = i + 1; j < count; j++) {
			reg1 = &dom->regions[j];

			if (!is_region_before(reg1, reg))
				continue;

			swap_region(reg, reg1);
		}
	}

	/* Remove covered regions */
	while(i < (count - 1)) {
		is_covered = false;
		reg = &dom->regions[i];

		for (j = i + 1; j < count; j++) {
			reg1 = &dom->regions[j];

			if (is_region_compatible(reg, reg1)) {
				is_covered = true;
				break;
			}
		}

		/* find a region is superset of reg, remove reg */
		if (is_covered) {
			for (j = i; j < (count - 1); j++)
				swap_region(&dom->regions[j],
					    &dom->regions[j + 1]);
			clear_region(&dom->regions[count - 1]);
			count--;
		} else
			i++;
	}
    
    return SBI_OK;
}