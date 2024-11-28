#ifndef __SBI_SMMTT_H__
#define __SBI_SMMTT_H__
#include <sbi/sbi_types.h>
typedef enum {
	SMMTT_BARE = 0,
#if __riscv_xlen == 32
	SMMTT_34,
	SMMTT_34_rw
#else
	SMMTT_46,
	SMMTT_46_rw,
	SMMTT_56,
	SMMTT_56_rw
#endif
} smmtt_mode_t;

unsigned int mttp_get_sdidlen();

void mttp_set(smmtt_mode_t mode, unsigned int sdid, uintptr_t ppn);

void mttp_get(smmtt_mode_t *mode, unsigned int *sdid, uintptr_t *ppn);

#endif //__SBI_SMMTT_H__