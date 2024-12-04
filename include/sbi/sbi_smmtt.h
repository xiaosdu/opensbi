#ifndef __SBI_SMMTT_H__
#define __SBI_SMMTT_H__
#include <sbi/sbi_types.h>
#include <sbi/smmtt_defs.h>

unsigned int mttp_get_sdidlen();

void mttp_set(smmtt_mode_t mode, unsigned int sdid, uintptr_t ppn);

void mttp_get(smmtt_mode_t *mode, unsigned int *sdid, uintptr_t *ppn);

#endif //__SBI_SMMTT_H__