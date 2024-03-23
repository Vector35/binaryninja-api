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

//*****************************************************************************
// structs and types
//*****************************************************************************
enum ppc_status_t {
    STATUS_ERROR_UNSPEC=-1, STATUS_SUCCESS=0, STATUS_UNDEF_INSTR
};


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
extern "C" int powerpc_init(int);
extern "C" void powerpc_release(void);
extern "C" int powerpc_decompose(const uint8_t *data, int size, uint32_t addr, 
	bool lil_end, struct decomp_result *result, int);
extern "C" int powerpc_disassemble(struct decomp_result *, char *buf, size_t len);

extern "C" const char *powerpc_reg_to_str(uint32_t rid, int);

