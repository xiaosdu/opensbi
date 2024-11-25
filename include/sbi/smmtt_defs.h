
#include <sbi/sbi_types.h>
/* SMMTT Modes */

typedef enum {
    SMMTT_BARE = 0,
#if defined(__SMMTT32)
    SMMTT_34,
#else
    SMMTT_46,
    SMMTT_56,
#endif
    SMMTT_MAX
} smmtt_mode;

#define MTTP32_MODE_MASK   _UL(0xC000000)
#define MTTP32_SDID_MASK   _UL(0x3FFC0000)
#define MTTP32_PPN_MASK    _UL(0x003FFFFF)

#define MTTP64_MODE_MASK   _ULL(0xF000000000000000)
#define MTTP64_SDID_MASK   _ULL(0x0FFFF00000000000)
#define MTTP64_PPN_MASK    _ULL(0x00000FFFFFFFFFFF)

#if defined(__SMMTT32)
#define MTTP_MODE_MASK     MTTP32_MODE_MASK
#define MTTP_SDID_MASK     MTTP32_SDID_MASK
#define MTTP_PPN_MASK      MTTP32_PPN_MASK
#else
#define MTTP_MODE_MASK     MTTP64_MODE_MASK
#define MTTP_SDID_MASK     MTTP64_SDID_MASK
#define MTTP_PPN_MASK      MTTP64_PPN_MASK
#endif

/* MTT Tables */

#define MTTL1_OFFSET_MASK        _ULL(0x0000000000f000)
#define MTTL1_INDEX_MASK         _ULL(0x00000001ff0000)
#define MTTL2_INDEX_MASK         _ULL(0x003ffffe000000)
#define MTTL3_INDEX_MASK         _ULL(0xffc00000000000)
#define MTTL2_PERMS_MASK         _ULL(0x00000001f00000)

typedef enum {
    MTT_L2_1G_DISALLOW      = 0b0000,
    MTT_L2_1G_ALLOW_RX      = 0b0001,
    MTT_L2_1G_ALLOW_RWX     = 0b0011,
    MTT_L2_MTT_L1_DIR       = 0b0100,
    MTT_L2_2M_PAGES         = 0b0111,
} smmtt_type;

typedef enum {
    MTT_L2_2M_PAGES_DISALLOWED = 0b00,
    MTT_L2_2M_PAGES_ALLOW_RX   = 0b01,
    MTT_L2_2M_PAGES_ALLOW_RWX  = 0b11,
} mttl2_2m_pages;

typedef enum {
    MTT_L1_DISALLOWED   = 0b0000,
    MTT_L1_ALLOW_RX     = 0b0001,
    MTT_L1_ALLOW_RWX    = 0b0011,
} mttl1_perms;

// Entries

typedef struct {
    uint64_t ppn : 44;
    uint64_t zero : 20;
} mttl3_entry;

typedef struct {
    uint64_t info : 44;
    uint64_t type : 4;
    uint64_t zero : 16;
} mttl2_entry;

typedef uint64_t mttl1_entry;

typedef union {
    uint64_t raw;
    mttl3_entry mttl3;
    mttl2_entry mttl2;
    mttl1_entry mttl1;
} mtt_entry;
