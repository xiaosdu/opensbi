#include <sbi/sbi_smmtt.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_bitops.h>
// #include <sbi/smmtt_defs.h>
unsigned int mttp_get_sdidlen()
{
	smmtt_mode_t mode;
	unsigned int sdid, sdidlen;
	uintptr_t ppn;
	// Save current values in mttp
	mttp_get(&mode, &sdid, &ppn);
	// Write all ones to SDID and get values back
	mttp_set(SMMTT_BARE, (unsigned int) -1, 0);
	mttp_get(NULL, &sdidlen, NULL);
	// Reset back old values
	mttp_set(mode, sdid, ppn);
	if(sdidlen == 0) {
		return 0;
	} else {
		return sbi_fls(sdidlen) + 1;
	}
}
void mttp_set(smmtt_mode_t mode, unsigned int sdid, uintptr_t ppn)
{
	uintptr_t mttp = (ppn & MTTP_PPN);
	mttp |= ((unsigned long) sdid << MTTP_SDID_SHIFT) & MTTP_SDID;
	mttp |= ((unsigned long) mode << MTTP_MODE_SHIFT) & MTTP_MODE;
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