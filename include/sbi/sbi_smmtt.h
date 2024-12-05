#ifndef __SBI_SMMTT_H__
#define __SBI_SMMTT_H__
#include <sbi/sbi_types.h>
#include <sbi/sbi_domain.h>
#include <sbi/smmtt_defs.h>

unsigned int mttp_get_sdidlen();

void mttp_set(smmtt_mode_t mode, unsigned int sdid, uintptr_t ppn);

void mttp_get(smmtt_mode_t *mode, unsigned int *sdid, uintptr_t *ppn);

int sbi_hart_smmtt_configure(struct sbi_scratch *scratch);

int sbi_smmtt_init(struct sbi_scratch *scratch, bool cold_boot);

#endif //__SBI_SMMTT_H__