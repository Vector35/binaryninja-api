/******************************************************************************

This is the layer that the architecture module uses to access disassemble
functionality.

Currently, it wraps capstone, but that could change in the future. It exists
precisely to make swapping out disassemblers easy, because disassembler details
(like capstone types) will not be intertwined in the architecture plugin code.

Also, with the disassembler object separate, we can link it against
easy-to-compile test harnesses like the speed test.

There are three main functions:

powerpc_init() - initializes this module
powerpc_release() - un-initializes this module
powerpc_decompose() - converts bytes into decomp_result
powerpc_disassemble() - converts decomp_result to string

Then some helpers if you need them:

******************************************************************************/

/* capstone stuff /usr/local/include/capstone */
#include "capstone/capstone.h"
#include "capstone/cs_priv.h"
#include "capstone/ppc.h"

#define PPC_CRX_REG_MASK	0x1ff
#define PPC_CRX_FLOAT_MASK	0x200

// TODO this is some sorta capstone baddy, where xori is showing as xnop's
// opcode. Maybe pulling capstone will fix, need for xori to correctly
// lift. Capstone is posting that XORI is 1452, though that is XNOP
#define PPC_BN_INS_XORI PPC_INS_XNOP

//*****************************************************************************
// structs and types
//*****************************************************************************
enum ppc_status_t {
    STATUS_ERROR_UNSPEC=-1, STATUS_SUCCESS=0, STATUS_UNDEF_INSTR
};

typedef enum ppc_insn_bn {
	PPC_INS_BN_FCMPO = PPC_INS_ENDING+1,
	PPC_INS_BN_XXPERMR,
	PPC_INS_BN_ENDING
} ppc_insn_bn;

typedef enum ppc_reg_bn {
	PPC_REG_BN_GQR0 = PPC_REG_ENDING+1,
	PPC_REG_BN_GQR1,
	PPC_REG_BN_GQR2,
	PPC_REG_BN_GQR3,
	PPC_REG_BN_GQR4,
	PPC_REG_BN_GQR5,
	PPC_REG_BN_GQR6,
	PPC_REG_BN_GQR7,
	PPC_REG_BN_ENDING
} ppc_reg_bn;

/* operand type */
enum operand_type_t { REG, VAL, LABEL };

struct decomp_request
{
    uint8_t *data;
	int size;
    uint32_t addr;
    bool lil_end;
};

struct decomp_result
{
	/* actual capstone handle used, in case caller wants to do extra stuff
		(this can be one of two handles opened for BE or LE disassembling) */
	csh handle;

    ppc_status_t status;

	cs_insn insn;
	cs_detail detail;
};

//*****************************************************************************
// function prototypes
//*****************************************************************************
int DoesQualifyForLocalDisassembly(const uint8_t *data, bool bigendian);
bool PerformLocalDisassembly(const uint8_t *data, uint64_t addr, size_t &len, decomp_result* res, bool bigendian);

extern "C" int powerpc_init(int);
extern "C" void powerpc_release(void);
extern "C" int powerpc_decompose(const uint8_t *data, int size, uint64_t addr, 
	bool lil_end, struct decomp_result *result, bool is_64bit, int cs_mode);
extern "C" int powerpc_disassemble(struct decomp_result *, char *buf, size_t len);

extern "C" const char *powerpc_reg_to_str(uint32_t rid, int cs_mode_arg);
extern "C" const uint32_t powerpc_crx_to_reg(uint32_t rid);
