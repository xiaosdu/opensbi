#ifndef __SBI_MEMREGION_H__
#define __SBI_MEMREGION_H__

#include <sbi/sbi_domain.h>

/** Domain access types */
enum sbi_domain_access {
	SBI_DOMAIN_READ = (1UL << 0),
	SBI_DOMAIN_WRITE = (1UL << 1),
	SBI_DOMAIN_EXECUTE = (1UL << 2),
	SBI_DOMAIN_MMIO = (1UL << 3)
};

/** Representation of OpenSBI domain memory region */
struct sbi_domain_memregion {
	/**
	 * Size of memory region as power of 2
	 * It has to be minimum 3 and maximum __riscv_xlen
	 */
	unsigned long order;
	/**
	 * Base address of memory region
	 * It must be 2^order aligned address
	 */
	unsigned long base;
	/** Flags representing memory region attributes */
#define SBI_DOMAIN_MEMREGION_M_READABLE		(1UL << 0)
#define SBI_DOMAIN_MEMREGION_M_WRITABLE		(1UL << 1)
#define SBI_DOMAIN_MEMREGION_M_EXECUTABLE	(1UL << 2)
#define SBI_DOMAIN_MEMREGION_SU_READABLE	(1UL << 3)
#define SBI_DOMAIN_MEMREGION_SU_WRITABLE	(1UL << 4)
#define SBI_DOMAIN_MEMREGION_SU_EXECUTABLE	(1UL << 5)

#define SBI_DOMAIN_MEMREGION_ACCESS_MASK	(0x3fUL)
#define SBI_DOMAIN_MEMREGION_M_ACCESS_MASK	(0x7UL)
#define SBI_DOMAIN_MEMREGION_SU_ACCESS_MASK	(0x38UL)

#define SBI_DOMAIN_MEMREGION_SU_ACCESS_SHIFT	(3)

#define SBI_DOMAIN_MEMREGION_SHARED_RDONLY		\
		(SBI_DOMAIN_MEMREGION_M_READABLE |	\
		 SBI_DOMAIN_MEMREGION_SU_READABLE)

#define SBI_DOMAIN_MEMREGION_SHARED_SUX_MRX		\
		(SBI_DOMAIN_MEMREGION_M_READABLE   |	\
		 SBI_DOMAIN_MEMREGION_M_EXECUTABLE |	\
		 SBI_DOMAIN_MEMREGION_SU_EXECUTABLE)

#define SBI_DOMAIN_MEMREGION_SHARED_SUX_MX		\
		(SBI_DOMAIN_MEMREGION_M_EXECUTABLE |	\
		 SBI_DOMAIN_MEMREGION_SU_EXECUTABLE)

#define SBI_DOMAIN_MEMREGION_SHARED_SURW_MRW		\
		(SBI_DOMAIN_MEMREGION_M_READABLE |	\
		 SBI_DOMAIN_MEMREGION_M_WRITABLE |	\
		 SBI_DOMAIN_MEMREGION_SU_READABLE|	\
		 SBI_DOMAIN_MEMREGION_SU_WRITABLE)

#define SBI_DOMAIN_MEMREGION_SHARED_SUR_MRW		\
		(SBI_DOMAIN_MEMREGION_M_READABLE |	\
		 SBI_DOMAIN_MEMREGION_M_WRITABLE |	\
		 SBI_DOMAIN_MEMREGION_SU_READABLE)

	/* Shared read-only region between M and SU mode */
#define SBI_DOMAIN_MEMREGION_IS_SUR_MR(__flags)			 \
		((__flags & SBI_DOMAIN_MEMREGION_ACCESS_MASK) == \
		 SBI_DOMAIN_MEMREGION_SHARED_RDONLY)

	/* Shared region: SU execute-only and M read/execute */
#define SBI_DOMAIN_MEMREGION_IS_SUX_MRX(__flags)		 \
		((__flags & SBI_DOMAIN_MEMREGION_ACCESS_MASK) == \
		 SBI_DOMAIN_MEMREGION_SHARED_SUX_MRX)

	/* Shared region: SU and M execute-only */
#define SBI_DOMAIN_MEMREGION_IS_SUX_MX(__flags)			 \
		((__flags & SBI_DOMAIN_MEMREGION_ACCESS_MASK) == \
		 SBI_DOMAIN_MEMREGION_SHARED_SUX_MX)

	/* Shared region: SU and M read/write */
#define SBI_DOMAIN_MEMREGION_IS_SURW_MRW(__flags)		 \
		((__flags & SBI_DOMAIN_MEMREGION_ACCESS_MASK) == \
		 SBI_DOMAIN_MEMREGION_SHARED_SURW_MRW)

	/* Shared region: SU read-only and M read/write */
#define SBI_DOMAIN_MEMREGION_IS_SUR_MRW(__flags)		 \
		((__flags & SBI_DOMAIN_MEMREGION_ACCESS_MASK) == \
		 SBI_DOMAIN_MEMREGION_SHARED_SUR_MRW)

	/*
	 * Check if region flags match with any of the above
	 * mentioned shared region type
	 */
#define SBI_DOMAIN_MEMREGION_IS_SHARED(_flags)			\
		(SBI_DOMAIN_MEMREGION_IS_SUR_MR(_flags)  ||	\
		 SBI_DOMAIN_MEMREGION_IS_SUX_MRX(_flags) ||	\
		 SBI_DOMAIN_MEMREGION_IS_SUX_MX(_flags)  ||	\
		 SBI_DOMAIN_MEMREGION_IS_SURW_MRW(_flags)||	\
		 SBI_DOMAIN_MEMREGION_IS_SUR_MRW(_flags))

#define SBI_DOMAIN_MEMREGION_M_ONLY_ACCESS(__flags)			\
		((__flags & SBI_DOMAIN_MEMREGION_M_ACCESS_MASK) &&	\
		 !(__flags & SBI_DOMAIN_MEMREGION_SU_ACCESS_MASK))

#define SBI_DOMAIN_MEMREGION_SU_ONLY_ACCESS(__flags)			\
		((__flags & SBI_DOMAIN_MEMREGION_SU_ACCESS_MASK)  &&	\
		 !(__flags & SBI_DOMAIN_MEMREGION_M_ACCESS_MASK))

/** Bit to control if permissions are enforced on all modes */
#define SBI_DOMAIN_MEMREGION_ENF_PERMISSIONS	(1UL << 6)

#define SBI_DOMAIN_MEMREGION_M_RWX		\
				(SBI_DOMAIN_MEMREGION_M_READABLE | \
				 SBI_DOMAIN_MEMREGION_M_WRITABLE | \
				 SBI_DOMAIN_MEMREGION_M_EXECUTABLE)

#define SBI_DOMAIN_MEMREGION_SU_RWX		\
				(SBI_DOMAIN_MEMREGION_SU_READABLE | \
				 SBI_DOMAIN_MEMREGION_SU_WRITABLE | \
				 SBI_DOMAIN_MEMREGION_SU_EXECUTABLE)

/* Unrestricted M-mode accesses but enfoced on SU-mode */
#define SBI_DOMAIN_MEMREGION_READABLE		\
				(SBI_DOMAIN_MEMREGION_SU_READABLE | \
				 SBI_DOMAIN_MEMREGION_M_RWX)
#define SBI_DOMAIN_MEMREGION_WRITEABLE		\
				(SBI_DOMAIN_MEMREGION_SU_WRITABLE | \
				 SBI_DOMAIN_MEMREGION_M_RWX)
#define SBI_DOMAIN_MEMREGION_EXECUTABLE		\
				(SBI_DOMAIN_MEMREGION_SU_EXECUTABLE | \
				 SBI_DOMAIN_MEMREGION_M_RWX)

/* Enforced accesses across all modes */
#define SBI_DOMAIN_MEMREGION_ENF_READABLE	\
				(SBI_DOMAIN_MEMREGION_SU_READABLE | \
				 SBI_DOMAIN_MEMREGION_M_READABLE)
#define SBI_DOMAIN_MEMREGION_ENF_WRITABLE	\
				(SBI_DOMAIN_MEMREGION_SU_WRITABLE | \
				 SBI_DOMAIN_MEMREGION_M_WRITABLE)
#define SBI_DOMAIN_MEMREGION_ENF_EXECUTABLE	\
				(SBI_DOMAIN_MEMREGION_SU_EXECUTABLE | \
				 SBI_DOMAIN_MEMREGION_M_EXECUTABLE)

#define SBI_DOMAIN_MEMREGION_MMIO		(1UL << 31)
	unsigned long flags;
};


/**
 * Initialize a domain memory region based on it's physical
 * address and size.
 *
 * @param addr start physical address of memory region
 * @param size physical size of memory region
 * @param flags memory region flags
 * @param reg pointer to memory region being initialized
 */
void sbi_domain_memregion_init(unsigned long addr,
				unsigned long size,
				unsigned long flags,
				struct sbi_domain_memregion *reg);

/**
 *
 * Traverse all of a domain's memory regions and sanitize
 * them, while making sure they are formatted properly
 *
 * @param dom the domain for which to sanitize regions
 */
int sbi_domain_memregions_sanitize(struct sbi_domain *dom);

/**
 * Check whether we can access specified address for given mode and
 * memory region flags under a domain
 * @param dom pointer to domain
 * @param addr the address to be checked
 * @param mode the privilege mode of access
 * @param access_flags bitmask of domain access types (enum sbi_domain_access)
 * @return true if access allowed otherwise false
 */
bool sbi_domain_check_addr(const struct sbi_domain *dom,
			   unsigned long addr, unsigned long mode,
			   unsigned long access_flags);

/**
 * Check whether we can access specified address range for given mode and
 * memory region flags under a domain
 * @param dom pointer to domain
 * @param addr the start of the address range to be checked
 * @param size the size of the address range to be checked
 * @param mode the privilege mode of access
 * @param access_flags bitmask of domain access types (enum sbi_domain_access)
 * @return TRUE if access allowed otherwise FALSE
 */
bool sbi_domain_check_addr_range(const struct sbi_domain *dom,
				 unsigned long addr, unsigned long size,
				 unsigned long mode,
				 unsigned long access_flags);

/** Dump domain memregion details on the console */
void sbi_domain_dump_memregions(const struct sbi_domain *dom, const char *suffix);

#endif