/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#ifndef __SBI_DOMAIN_H__
#define __SBI_DOMAIN_H__

#include <sbi/riscv_locks.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_hartmask.h>
#include <sbi/sbi_domain_context.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_memregion.h>
#include <sbi/smmtt_defs.h>

struct sbi_scratch;

/** Domain access types */
enum sbi_domain_access {
	SBI_DOMAIN_READ = (1UL << 0),
	SBI_DOMAIN_WRITE = (1UL << 1),
	SBI_DOMAIN_EXECUTE = (1UL << 2),
	SBI_DOMAIN_MMIO = (1UL << 3)
};

/** Maximum number of domains */
#define SBI_DOMAIN_MAX_INDEX			32

/** Representation of OpenSBI domain */
struct sbi_domain {
	/**
	 * Logical index of this domain
	 * Note: This set by sbi_domain_finalize() in the coldboot path
	 */
	u32 index;
	/**
	 * HARTs assigned to this domain
	 * Note: This set by sbi_domain_init() and sbi_domain_finalize()
	 * in the coldboot path
	 */
	struct sbi_hartmask assigned_harts;
	/** Spinlock for accessing assigned_harts */
	spinlock_t assigned_harts_lock;
	/** Name of this domain */
	char name[64];
	/** Possible HARTs in this domain */
	const struct sbi_hartmask *possible_harts;
	/** Contexts for possible HARTs indexed by hartindex */
	struct sbi_context *hartindex_to_context_table[SBI_HARTMASK_MAX_BITS];
	/** Array of memory regions terminated by a region with order zero */
	struct sbi_domain_memregion *regions;
	/** HART id of the HART booting this domain */
	u32 boot_hartid;
	/** Arg1 (or 'a1' register) of next booting stage for this domain */
	unsigned long next_arg1;
	/** Address of next booting stage for this domain */
	unsigned long next_addr;
	/** Privilege mode of next booting stage for this domain */
	unsigned long next_mode;
	/** Is domain allowed to reset the system */
	bool system_reset_allowed;
	/** Is domain allowed to suspend the system */
	bool system_suspend_allowed;
	/** Identifies whether to include the firmware region */
	bool fw_region_inited;
	/** Current SMMTT mode */
	smmtt_mode smmtt_mode;
	/** SMMTT base table */
	void *mtt;
	/** Current isolation mode */
	enum sbi_isolation_method isol_mode;
};

/** The root domain instance */
extern struct sbi_domain root;

/** Get pointer to sbi_domain from HART index */
struct sbi_domain *sbi_hartindex_to_domain(u32 hartindex);

/** Update HART local pointer to point to specified domain */
void sbi_update_hartindex_to_domain(u32 hartindex, struct sbi_domain *dom);

/** Get pointer to sbi_domain for current HART */
#define sbi_domain_thishart_ptr() \
	sbi_hartindex_to_domain(sbi_hartid_to_hartindex(current_hartid()))

/** Index to domain table */
extern struct sbi_domain *domidx_to_domain_table[];

/** Get pointer to sbi_domain from index */
#define sbi_index_to_domain(__index) \
	domidx_to_domain_table[__index]

/** Iterate over each domain */
#define sbi_domain_for_each(__i, __d) \
	for ((__i) = 0; ((__d) = sbi_index_to_domain(__i)); (__i)++)

/** Iterate over each memory region of a domain */
#define sbi_domain_for_each_memregion(__d, __r) \
	for ((__r) = (__d)->regions; (__r)->size; (__r)++)

/**
 * Check whether given HART is assigned to specified domain
 * @param dom pointer to domain
 * @param hartid the HART ID
 * @return true if HART is assigned to domain otherwise false
 */
bool sbi_domain_is_assigned_hart(const struct sbi_domain *dom, u32 hartid);

/**
 * Get ulong assigned HART mask for given domain and HART base ID
 * @param dom pointer to domain
 * @param hbase the HART base ID
 * @return ulong possible HART mask
 * Note: the return ulong mask will be set to zero on failure.
 */
ulong sbi_domain_get_assigned_hartmask(const struct sbi_domain *dom,
				       ulong hbase);

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

/** Dump domain details on the console */
void sbi_domain_dump(const struct sbi_domain *dom, const char *suffix);

/** Dump all domain details on the console */
void sbi_domain_dump_all(const char *suffix);

/**
 * Register a new domain
 * @param dom pointer to domain
 * @param assign_mask pointer to HART mask of HARTs assigned to the domain
 *
 * @return 0 on success and negative error code on failure
 */
int sbi_domain_register(struct sbi_domain *dom,
			const struct sbi_hartmask *assign_mask);

/**
 * Add a memory region to the root domain
 * @param reg pointer to the memory region to be added
 *
 * @return 0 on success
 * @return SBI_EALREADY if memory region conflicts with the existing one
 * @return SBI_EINVAL otherwise
 */
int sbi_domain_root_add_memregion(const struct sbi_domain_memregion *reg);

/**
 * Add a memory range with its flags to the root domain
 * @param addr start physical address of memory range
 * @param size physical size of memory range
 * @param align alignment of memory region
 * @param region_flags memory range flags
 *
 * @return 0 on success
 * @return SBI_EALREADY if memory region conflicts with the existing one
 * @return SBI_EINVAL otherwise
 */
int sbi_domain_root_add_memrange(unsigned long addr, unsigned long size,
			   unsigned long align, unsigned long region_flags);

/** Finalize domain tables and startup non-root domains */
int sbi_domain_finalize(struct sbi_scratch *scratch, u32 cold_hartid);

/** Initialize domains */
int sbi_domain_init(struct sbi_scratch *scratch, u32 cold_hartid);

int sanitize_domain(struct sbi_domain *dom);

#endif
