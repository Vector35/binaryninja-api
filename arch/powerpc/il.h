/* these are the flags in cr0
	(the default condition field in condition register CR)

PPC docs conceptualize this in a reverse bit order of sorts:

     CR0         CR1
 ----------- ----------- 
 b0 b1 b2 b3 b4 b5 b6 b7 
+--+--+--+--+--+--+--+--+ ...
|LT|GT|EQ|SO|LT|GT|EQ|SO|
+--+--+--+--+--+--+--+--+  

or is it: |SO|LT|GT|EQ
eg: cmp a, b
if a<b  then c=0b100 (not setting SO, setting LT)
if a>b  then c=0b010 (not setting SO, setting GT)
if a==b then c=0b001 (not setting SO, setting EQ)

FOR FLOATING POINT
if ((frA) is a NaN or (frB) is a NaN)   then c=0b0001
else if (frA)< (frB)                    then c=0b1000
else if (frA)> (frB)                    then c=0b0100
else if (frA)==(frB)                    then c=0b0010
 */

typedef enum
{
    PPC_SUF_S=0,
    PPC_SUF_U=1,
    PPC_SUF_F=2,
    PPC_SUF_SZ=3
} ppc_suf;

#define IL_FLOAT_FLAG_NAN   (1 << 8)
#define IL_FLOAT_FLAG_LT    (8 << 8)
#define IL_FLOAT_FLAG_GT    (4 << 8)
#define IL_FLOAT_FLAG_EQ    (2 << 8)

#define IL_FLAG_LT 0
#define IL_FLAG_GT 1
#define IL_FLAG_EQ 2
#define IL_FLAG_SO 3
#define IL_FLAG_LT_1 4
#define IL_FLAG_GT_1 5
#define IL_FLAG_EQ_1 6
#define IL_FLAG_SO_1 7
#define IL_FLAG_LT_2 8
#define IL_FLAG_GT_2 9
#define IL_FLAG_EQ_2 10
#define IL_FLAG_SO_2 11
#define IL_FLAG_LT_3 12
#define IL_FLAG_GT_3 13
#define IL_FLAG_EQ_3 14
#define IL_FLAG_SO_3 15
#define IL_FLAG_LT_4 16
#define IL_FLAG_GT_4 17
#define IL_FLAG_EQ_4 18
#define IL_FLAG_SO_4 19
#define IL_FLAG_LT_5 20
#define IL_FLAG_GT_5 21
#define IL_FLAG_EQ_5 22
#define IL_FLAG_SO_5 23
#define IL_FLAG_LT_6 24
#define IL_FLAG_GT_6 25
#define IL_FLAG_EQ_6 26
#define IL_FLAG_SO_6 27
#define IL_FLAG_LT_7 28
#define IL_FLAG_GT_7 29
#define IL_FLAG_EQ_7 30
#define IL_FLAG_SO_7 31

/* and now the fixed-point exception register XER */
#define IL_FLAG_XER_SO 32 /* [s]ummary [o]verflow */
#define IL_FLAG_XER_OV 33 /* [ov]erflow */
#define IL_FLAG_XER_CA 34 /* [ca]rry */

/* the different types of influence an instruction can have over flags */
#define IL_FLAGWRITE_NONE 0
#define IL_FLAGWRITE_CR0_S 1
#define IL_FLAGWRITE_CR0_U 2
#define IL_FLAGWRITE_CR0_F 3
#define IL_FLAGWRITE_CR1_S 4
#define IL_FLAGWRITE_CR1_U 5
#define IL_FLAGWRITE_CR1_F 6
#define IL_FLAGWRITE_CR2_S 7
#define IL_FLAGWRITE_CR2_U 8
#define IL_FLAGWRITE_CR2_F 9
#define IL_FLAGWRITE_CR3_S 10
#define IL_FLAGWRITE_CR3_U 11
#define IL_FLAGWRITE_CR3_F 12
#define IL_FLAGWRITE_CR4_S 13
#define IL_FLAGWRITE_CR4_U 14
#define IL_FLAGWRITE_CR4_F 15
#define IL_FLAGWRITE_CR5_S 16
#define IL_FLAGWRITE_CR5_U 17
#define IL_FLAGWRITE_CR5_F 18
#define IL_FLAGWRITE_CR6_S 19
#define IL_FLAGWRITE_CR6_U 20
#define IL_FLAGWRITE_CR6_F 21
#define IL_FLAGWRITE_CR7_S 22
#define IL_FLAGWRITE_CR7_U 23
#define IL_FLAGWRITE_CR7_F 24
#define IL_FLAGWRITE_XER 25
#define IL_FLAGWRITE_XER_CA 26
#define IL_FLAGWRITE_XER_OV_SO 27

#define IL_FLAGWRITE_MTCR0 28
#define IL_FLAGWRITE_MTCR1 29
#define IL_FLAGWRITE_MTCR2 30
#define IL_FLAGWRITE_MTCR3 31
#define IL_FLAGWRITE_MTCR4 32
#define IL_FLAGWRITE_MTCR5 33
#define IL_FLAGWRITE_MTCR6 34
#define IL_FLAGWRITE_MTCR7 35

#define IL_FLAGWRITE_INVL0 38
#define IL_FLAGWRITE_INVL1 39
#define IL_FLAGWRITE_INVL2 40
#define IL_FLAGWRITE_INVL3 41
#define IL_FLAGWRITE_INVL4 42
#define IL_FLAGWRITE_INVL5 43
#define IL_FLAGWRITE_INVL6 44
#define IL_FLAGWRITE_INVL7 45

#define IL_FLAGWRITE_INVALL 48

/* the different classes of writes to each cr */
#define IL_FLAGCLASS_NONE 0
#define IL_FLAGCLASS_CR0_S 1
#define IL_FLAGCLASS_CR0_U 2
#define IL_FLAGCLASS_CR0_F 3
#define IL_FLAGCLASS_CR1_S 4
#define IL_FLAGCLASS_CR1_U 5
#define IL_FLAGCLASS_CR1_F 6
#define IL_FLAGCLASS_CR2_S 7
#define IL_FLAGCLASS_CR2_U 8
#define IL_FLAGCLASS_CR2_F 9
#define IL_FLAGCLASS_CR3_S 10
#define IL_FLAGCLASS_CR3_U 11
#define IL_FLAGCLASS_CR3_F 12
#define IL_FLAGCLASS_CR4_S 13
#define IL_FLAGCLASS_CR4_U 14
#define IL_FLAGCLASS_CR4_F 15
#define IL_FLAGCLASS_CR5_S 16
#define IL_FLAGCLASS_CR5_U 17
#define IL_FLAGCLASS_CR5_F 18
#define IL_FLAGCLASS_CR6_S 19
#define IL_FLAGCLASS_CR6_U 20
#define IL_FLAGCLASS_CR6_F 21
#define IL_FLAGCLASS_CR7_S 22
#define IL_FLAGCLASS_CR7_U 23
#define IL_FLAGCLASS_CR7_F 24

#define IL_FLAGGROUP_CR0_LT (0 + 0)
#define IL_FLAGGROUP_CR0_LE (0 + 1)
#define IL_FLAGGROUP_CR0_GT (0 + 2)
#define IL_FLAGGROUP_CR0_GE (0 + 3)
#define IL_FLAGGROUP_CR0_EQ (0 + 4)
#define IL_FLAGGROUP_CR0_NE (0 + 5)

#define IL_FLAGGROUP_CR1_LT (10 + 0)
#define IL_FLAGGROUP_CR1_LE (10 + 1)
#define IL_FLAGGROUP_CR1_GT (10 + 2)
#define IL_FLAGGROUP_CR1_GE (10 + 3)
#define IL_FLAGGROUP_CR1_EQ (10 + 4)
#define IL_FLAGGROUP_CR1_NE (10 + 5)

#define IL_FLAGGROUP_CR2_LT (20 + 0)
#define IL_FLAGGROUP_CR2_LE (20 + 1)
#define IL_FLAGGROUP_CR2_GT (20 + 2)
#define IL_FLAGGROUP_CR2_GE (20 + 3)
#define IL_FLAGGROUP_CR2_EQ (20 + 4)
#define IL_FLAGGROUP_CR2_NE (20 + 5)

#define IL_FLAGGROUP_CR3_LT (30 + 0)
#define IL_FLAGGROUP_CR3_LE (30 + 1)
#define IL_FLAGGROUP_CR3_GT (30 + 2)
#define IL_FLAGGROUP_CR3_GE (30 + 3)
#define IL_FLAGGROUP_CR3_EQ (30 + 4)
#define IL_FLAGGROUP_CR3_NE (30 + 5)

#define IL_FLAGGROUP_CR4_LT (40 + 0)
#define IL_FLAGGROUP_CR4_LE (40 + 1)
#define IL_FLAGGROUP_CR4_GT (40 + 2)
#define IL_FLAGGROUP_CR4_GE (40 + 3)
#define IL_FLAGGROUP_CR4_EQ (40 + 4)
#define IL_FLAGGROUP_CR4_NE (40 + 5)

#define IL_FLAGGROUP_CR5_LT (50 + 0)
#define IL_FLAGGROUP_CR5_LE (50 + 1)
#define IL_FLAGGROUP_CR5_GT (50 + 2)
#define IL_FLAGGROUP_CR5_GE (50 + 3)
#define IL_FLAGGROUP_CR5_EQ (50 + 4)
#define IL_FLAGGROUP_CR5_NE (50 + 5)

#define IL_FLAGGROUP_CR6_LT (60 + 0)
#define IL_FLAGGROUP_CR6_LE (60 + 1)
#define IL_FLAGGROUP_CR6_GT (60 + 2)
#define IL_FLAGGROUP_CR6_GE (60 + 3)
#define IL_FLAGGROUP_CR6_EQ (60 + 4)
#define IL_FLAGGROUP_CR6_NE (60 + 5)

#define IL_FLAGGROUP_CR7_LT (70 + 0)
#define IL_FLAGGROUP_CR7_LE (70 + 1)
#define IL_FLAGGROUP_CR7_GT (70 + 2)
#define IL_FLAGGROUP_CR7_GE (70 + 3)
#define IL_FLAGGROUP_CR7_EQ (70 + 4)
#define IL_FLAGGROUP_CR7_NE (70 + 5)

enum PPCIntrinsic : uint32_t
{
    PPC_INTRIN_CNTLZW,
    PPC_INTRIN_FRSP,
    PPC_INTRIN_END,
    PPC_PS_INTRIN_QUANTIZE,
    PPC_PS_INTRIN_DEQUANTIZE,
    PPC_PS_INTRIN_END,
	PPC_INTRIN_INVALID = 0xFFFFFFFF,
};


bool GetLowLevelILForPPCInstruction(Architecture *arch, LowLevelILFunction& il, const uint8_t *data, uint64_t addr, decomp_result *res, bool le);
