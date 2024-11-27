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
#include <sbi/sbi_list.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_hartmask.h>
#include <sbi/sbi_domain_context.h>
#include <sbi/sbi_domain_data.h>
#include <sbi/sbi_memregion.h>

struct sbi_scratch;

/** Representation of OpenSBI domain */
struct sbi_domain {
	/** Node in linked list of domains */
	struct sbi_dlist node;
	/** Internal state of per-domain data */
	struct sbi_domain_data_priv data_priv;
	/** Logical index of this domain */
	u32 index;
	/** HARTs assigned to this domain */
	struct sbi_hartmask assigned_harts;
	/** Spinlock for accessing assigned_harts */
	spinlock_t assigned_harts_lock;
	/** Name of this domain */
	char name[64];
	/** Possible HARTs in this domain */
	const struct sbi_hartmask *possible_harts;
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
};

/** The root domain instance */
extern struct sbi_domain root;

/** Get pointer to sbi_domain from HART index */
struct sbi_domain *sbi_hartindex_to_domain(u32 hartindex);

/** Update HART local pointer to point to specified domain */
void sbi_update_hartindex_to_domain(u32 hartindex, struct sbi_domain *dom);

/** Get pointer to sbi_domain for current HART */
#define sbi_domain_thishart_ptr() \
	sbi_hartindex_to_domain(current_hartindex())

/** Head of linked list of domains */
extern struct sbi_dlist domain_list;

/** Iterate over each domain */
#define sbi_domain_for_each(__d) \
	sbi_list_for_each_entry(__d, &domain_list, node)

/** Iterate over each memory region of a domain */
#define sbi_domain_for_each_memregion(__d, __r) \
	for ((__r) = (__d)->regions; (__r)->order; (__r)++)

/**
 * Check whether given HART is assigned to specified domain
 * @param dom pointer to domain
 * @param hartindex the HART index
 * @return true if HART is assigned to domain otherwise false
 */
bool sbi_domain_is_assigned_hart(const struct sbi_domain *dom, u32 hartindex);

/**
 * Get the assigned HART mask for given domain
 * @param dom pointer to domain
 * @param mask the output hartmask to fill
 * @return 0 on success and SBI_Exxx (< 0) on failure
 */
int sbi_domain_get_assigned_hartmask(const struct sbi_domain *dom,
				     struct sbi_hartmask *mask);

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

#endif
