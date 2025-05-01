// Copyright (c) 2006-2015, Rusty Wagner
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that
// the following conditions are met:
//
//    * Redistributions of source code must retain the above copyright notice, this list of conditions and the
//      following disclaimer.
//    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
//      the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifdef __cplusplus
namespace asmx86
{
#endif

#ifndef __CODEGENX86_COMMON
#define __CODEGENX86_COMMON

// Define X86_CODEGEN_ALWAYS_INLINE if and only if the primary use of the library is to emit
// code where the registers are not allocated at runtime (i.e. the bytes of the instruction
// can be determined at compile time).  Runtime computed immediates are OK in all cases.
// This flag can improve code output for this use case.  Use of this flag where registers
// are allocated at runtime may increase code size.
#ifdef X86_CODEGEN_ALWAYS_INLINE
	#ifdef WIN32
		#define __alwaysinline __forceinline
	#else
		#define __alwaysinline __attribute__((always_inline))
	#endif
#else
	#define __alwaysinline
#endif

// Define X86_CODEGEN_DEBUG to generate assertion failures if an attempt is made to
// generate invalid code.  If this flag is not used, attempts to generate invalid code
// will produce undefined results (the check is omitted for better speed and code size).
#ifdef X86_CODEGEN_DEBUG
	#define __CGX86_LINE_STRING_FINAL(line) #line
	#define __CGX86_LINE_STRING(line) __CGX86_LINE_STRING_FINAL(line)
	#define __CGX86_LOCATION_STRING __FILE__ ", line " __CGX86_LINE_STRING(__LINE__)
	#define __CGX86_LOCATION __CGX86_LOCATION_STRING, sizeof(__CGX86_LOCATION_STRING) - 1
	#ifdef WIN32
		#define __CGX86_ERROR_STRING(str) "Assertion failure: " str "\n"
	#else
		#define __CGX86_ERROR_STRING(str) "): " str "\n"
	#endif
	#define __CGX86_ASSERT(test, str) ((test) ? 0 : (__cgx86_assert_failure(__CGX86_ERROR_STRING(str), sizeof(__CGX86_ERROR_STRING(str)) - 1, loc, locLen), 0))
	static __inline void __cgx86_assert_failure(const char* str, size_t len, const char* loc, size_t locLen)
	{
		#ifdef WIN32
			MessageBoxA(NULL, str, loc, MB_OK | MB_ICONSTOP);
			__debugbreak();
		#else
			write(2 /* stderr */, "Assertion failure (", 19);
			write(2 /* stderr */, loc, locLen);
			write(2 /* stderr */, str, len);
			#if defined(__i386__) || defined(__x86_64__)
				__asm__ ("int3");
			#else
				_exit(1);
			#endif
		#endif
	}
	#define __CGX86_ASSERT_PARAM_DECL , const char* loc, size_t locLen
	#define __CGX86_ASSERT_PARAMS , loc, locLen
	#define __CGX86_LOCATION_PARAM , __CGX86_LOCATION
#else
	#define __CGX86_ASSERT(test, str)
	#define __CGX86_ASSERT_PARAM_DECL
	#define __CGX86_ASSERT_PARAMS
	#define __CGX86_LOCATION_PARAM
#endif

	struct JumpLabel
	{
		uint8_t* chain;
		uint8_t* addr;
		int nearJump;
	};
#ifndef __cplusplus
	typedef struct JumpLabel JumpLabel;
#endif

	enum __JumpTargetType
	{
		__JUMPTARGET_JO = 0,
		__JUMPTARGET_JNO,
		__JUMPTARGET_JB,
		__JUMPTARGET_JAE,
		__JUMPTARGET_JE,
		__JUMPTARGET_JNE,
		__JUMPTARGET_JBE,
		__JUMPTARGET_JA,
		__JUMPTARGET_JS,
		__JUMPTARGET_JNS,
		__JUMPTARGET_JPE,
		__JUMPTARGET_JPO,
		__JUMPTARGET_JL,
		__JUMPTARGET_JGE,
		__JUMPTARGET_JLE,
		__JUMPTARGET_JG,
		__JUMPTARGET_ALWAYS,
		__JUMPTARGET_JCXZ,
		__JUMPTARGET_JECXZ,
		__JUMPTARGET_JRCXZ
	};
#ifndef __cplusplus
	typedef enum __JumpTargetType __JumpTargetType;
#endif


#define __REG_PARAM(n) OperandType n
#define __IMM8_PARAM(n) int8_t n
#define __IMM16_PARAM(n) int16_t n
#define __IMM32_PARAM(n) int32_t n
#define __IMM64_PARAM(n) int64_t n
#define __PTR_PARAM(n) const void* n
#define __TARGET_PARAM(n) JumpLabel* n

#define __REG __REG_PARAM
#define __IMM8 __IMM8_PARAM
#define __IMM16 __IMM16_PARAM
#define __IMM32 __IMM32_PARAM
#define __IMM64 __IMM64_PARAM
#define __PTR __PTR_PARAM
#define __TARGET __TARGET_PARAM

#ifdef __GNUC__
// GCC does not produce optimal code with inlined structure params, pass each member individually
#define __MEM_PARAM(n) OperandType n ## _base, OperandType n ## _index, uint8_t n ## _scale, ssize_t n ## _offset
#define __MEM __MEM_PARAM
#define __MEMOP(n) n ## _base, n ## _index, n ## _scale, n ## _offset
#define __MEM_BASE(n) n ## _base
#define __MEM_INDEX(n) n ## _index
#define __MEM_SCALE(n) n ## _scale
#define __MEM_OFFSET(n) n ## _offset
#else
// VC++ macro handling is incapable of using separate parameters for memory address components,
// use a structure to hold the values
	struct __cgx86_mem_struct
	{
		OperandType base;
		OperandType index;
		uint8_t scale;
		ssize_t offset;
	};
#ifndef __cplusplus
	typedef struct __cgx86_mem_struct __cgx86_mem_struct;
#endif

#define __MEM_PARAM(n) __cgx86_mem_struct n
#define __MEM __MEM_PARAM
#define __MEMOP(n) n
#define __MEM_BASE(n) n.base
#define __MEM_INDEX(n) n.index
#define __MEM_SCALE(n) n.scale
#define __MEM_OFFSET(n) n.offset
#endif

#ifdef X86_CODEGEN_DEBUG
#define __CONTEXT_PARAMS uint8_t* buf, const void* (*translate)(const void* buf, void* param), void* param, int wr, const char* loc, size_t locLen
#define __CONTEXT buf, translate, param, wr, loc, locLen
#define __EMIT_CONTEXT(buf) buf, 0, 0, 1, __CGX86_LOCATION
#define __EMIT_CONTEXT_OFFSET(buf, n) (&(buf)[n]), 0, 0, 1, __CGX86_LOCATION
#define __EMIT_ALTEXEC_CONTEXT(buf, xlat, param) buf, xlat, param, 1, __CGX86_LOCATION
#define __EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, n) (&(buf)[n]), xlat, param, 1, __CGX86_LOCATION
#define __LENGTH_CONTEXT 0, 0, 0, 0, __CGX86_LOCATION
#define __NO_ASSERT (void)loc; (void)locLen;
#else
#define __CONTEXT_PARAMS uint8_t* buf, const void* (*translate)(const void* buf, void* param), void* param, int wr
#define __CONTEXT buf, translate, param, wr
#define __EMIT_CONTEXT(buf) buf, 0, 0, 1
#define __EMIT_CONTEXT_OFFSET(buf, n) (&(buf)[n]), 0, 0, 1
#define __EMIT_ALTEXEC_CONTEXT(buf, xlat, param) buf, xlat, param, 1
#define __EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, n) (&(buf)[n]), xlat, param, 1
#define __LENGTH_CONTEXT 0, 0, 0, 0
#define __NO_ASSERT
#endif
#define __TRANSLATE_UNUSED (void)translate; (void)param;

#define __DEF_INSTR_0(n) static __inline size_t __alwaysinline __PREFIX(n) (__CONTEXT_PARAMS)
#define __DEF_INSTR_1(n, t, ta) static __inline size_t __alwaysinline __NAME(n, t) (__CONTEXT_PARAMS, ta(a))
#define __DEF_INSTR_2(n, t, ta, tb) static __inline size_t __alwaysinline __NAME(n, t) (__CONTEXT_PARAMS, ta(a), tb(b))
#define __DEF_INSTR_3(n, t, ta, tb, tc) static __inline size_t __alwaysinline __NAME(n, t) (__CONTEXT_PARAMS, ta(a), tb(b), tc(c))
#define __DEF_INSTR_0_ARG(n, t, arg) static __inline size_t __alwaysinline __NAME(n, t) (__CONTEXT_PARAMS, arg)
#define __DEF_INSTR_1_ARG(n, t, ta, arg) static __inline size_t __alwaysinline __NAME(n, t) (__CONTEXT_PARAMS, arg, ta(a))
#define __DEF_INSTR_2_ARG(n, t, ta, tb, arg) static __inline size_t __alwaysinline __NAME(n, t) (__CONTEXT_PARAMS, arg, ta(a), tb(b))
#define __DEF_INSTR_3_ARG(n, t, ta, tb, tc, arg) static __inline size_t __alwaysinline __NAME(n, t) (__CONTEXT_PARAMS, arg, ta(a), tb(b), tc(c))

#define __SEGPREFIX(buf, wr, s, e) (__segprefix(buf, wr, s), e + 1)
#define __LOCKPREFIX(e) (__WRITE_BUF_8(0, 0xf0), e + 1)

#define X86_DECLARE_JUMP_LABEL(n) JumpLabel n = {0, 0, 0}
#define X86_DECLARE_NEAR_JUMP_LABEL(n) JumpLabel n = {0, 0, 1} // For 64-bit labels that are always within +/-2GB
#define X86_INIT_JUMP_LABEL(n) (n.chain = 0, n.addr = 0, n.nearJump = 0)
#define X86_INIT_NEAR_JUMP_LABEL(n) (n.chain = 0, n.addr = 0, n.nearJump = 1)

#define __WRITE_BUF_8(offset, val) ((wr) ? ((buf)[offset] = (val)) : (val))
#define __WRITE_BUF_8_8(offset, a, b) __WRITE_BUF_16(offset, (int16_t)(((b) << 8) | ((a) & 0xff)))
#define __WRITE_BUF_8_8_8_8(offset, a, b, c, d) __WRITE_BUF_32(offset, (int32_t)(((d) << 24) | (((c) & 0xff) << 16) | (((b) & 0xff) << 8) | ((a) & 0xff)))
#define __WRITE_BUF_16(offset, val) ((wr) ? (*((int16_t*)&(buf)[offset]) = (val)) : (val))
#define __WRITE_BUF_32(offset, val) ((wr) ? (*((int32_t*)&(buf)[offset]) = (val)) : (val))
#define __WRITE_BUF_64(offset, val) ((wr) ? (*((int64_t*)&(buf)[offset]) = (val)) : (val))
#define __WRITE_BUF_8_ALWAYS(offset, val) (buf)[offset] = (val)
#define __WRITE_BUF_8_8_ALWAYS(offset, a, b) __WRITE_BUF_16_ALWAYS(offset, (int16_t)(((b) << 8) | ((a) & 0xff)))
#define __WRITE_BUF_16_ALWAYS(offset, val) *((int16_t*)&(buf)[offset]) = (val)
#define __WRITE_BUF_32_ALWAYS(offset, val) *((int32_t*)&(buf)[offset]) = (val)
#define __WRITE_BUF_64_ALWAYS(offset, val) *((int64_t*)&(buf)[offset]) = (val)
#define __BUF_OFFSET(offset) (&(buf)[offset])

#ifdef X86_CODEGEN_DEBUG
#define __CONTEXT_OFFSET(offset) __BUF_OFFSET(offset), translate, param, wr, loc, locLen
#else
#define __CONTEXT_OFFSET(offset) __BUF_OFFSET(offset), translate, param, wr
#endif

#define X86_MAX_EMIT_LENGTH 16

// REX prefix macros, use of (n & 8) instead of (n >= 8) is critical, see __reg8_64bit function
#define __REX(v) (0x40 | (v))
#define __REX_64 8
#define __REX_REG(n) (((n) & 8) ? 4 : 0)
#define __REX_INDEX(n) (((n) & 8) ? 2 : 0)
#define __REX_RM(n) (((n) & 8) ? 1 : 0)
#define __REX_OPCODE(n) (((n) & 8) ? 1 : 0)


	// Memory operand constructors
#ifdef __GNUC__
#define X86_MEM(base, offset) (base), NONE, 1, (offset)
#define X86_MEM_INDEX(base, index, scale, offset) (base), (index), (scale), (offset)
#define X86_MEM_PTR(ptr) NONE, NONE, 1, (int32_t)(size_t)(ptr)
#define X86_MEM_PARAM(base, index, scale, offset) (base), (index), (scale), (offset)
#else
#define X86_MEM(base, offset) __cgx86_mem((base), NONE, 1, (offset))
#define X86_MEM_INDEX(base, index, scale, offset) __cgx86_mem((base), (index), (scale), (offset))
#define X86_MEM_PTR(ptr) __cgx86_mem(NONE, NONE, 1, (int32_t)(size_t)(ptr))
#define X86_MEM_PARAM(m) (m)

	static __inline __cgx86_mem_struct __cgx86_mem(OperandType base, OperandType index, uint8_t scale, ssize_t offset)
	{
		__cgx86_mem_struct m;
		m.base = base;
		m.index = index;
		m.scale = scale;
		m.offset = offset;
		return m;
	}
#endif

#ifdef X86_CODEGEN_DEBUG
#define __REG_DEBUG_PARAM_DECL , const char* loc, size_t locLen
#define __REG_DEBUG_PARAMS , loc, locLen
#else
#define __REG_DEBUG_PARAM_DECL
#define __REG_DEBUG_PARAMS
#endif

	// Register operand to register index routines
	static __inline uint8_t __alwaysinline __reg8_32bit(OperandType r  __REG_DEBUG_PARAM_DECL)
	{
		__CGX86_ASSERT((r >= REG_AL) && (r <= REG_BH), "Bad 8-bit register");
		return (uint8_t)(r - REG_AL);
	}

	static __inline uint8_t __alwaysinline __reg8_64bit(OperandType r  __REG_DEBUG_PARAM_DECL)
	{
		__CGX86_ASSERT((r >= REG_AL) && (r <= REG_R15B), "Bad 8-bit register");
		if (r < REG_SPL)
		{
			// Legacy usage, no REX involved
			return (uint8_t)(r - REG_AL);
		}
		else if (r >= REG_R8B)
		{
			// Normal R8-R15 operation, bit 3 is set so __REX macros will set the proper REX bit,
			// bit 4 is set so assertion checks know it is an 8bit register
			return (uint8_t)(r - REG_R8B + 24);
		}
		else
		{
			// SPL, BPL, SIL, or DIL access.  These only work if a REX prefix is present, but we
			// don't want to actually set any REX bits.  To allow this, bit 3 is not set, so
			// __REX macros above will not set the REX bit, but the presence of a REX byte is
			// forced as the value is >= 8
			return (uint8_t)(r - REG_SPL + 20);
		}
	}

	static __inline uint8_t __alwaysinline __reg16_32bit(OperandType r  __REG_DEBUG_PARAM_DECL)
	{
		__CGX86_ASSERT((r >= REG_AX) && (r <= REG_DI), "Bad 16-bit register");
		return (uint8_t)(r - REG_AX);
	}

	static __inline uint8_t __alwaysinline __reg16_64bit(OperandType r  __REG_DEBUG_PARAM_DECL)
	{
		__CGX86_ASSERT((r >= REG_AX) && (r <= REG_R15W), "Bad 16-bit register");
		return (uint8_t)(r - REG_AX);
	}

	static __inline uint8_t __alwaysinline __reg32_32bit(OperandType r  __REG_DEBUG_PARAM_DECL)
	{
		__CGX86_ASSERT((r >= REG_EAX) && (r <= REG_EDI), "Bad 32-bit register");
		return (uint8_t)(r - REG_EAX);
	}

	static __inline uint8_t __alwaysinline __reg32_64bit(OperandType r  __REG_DEBUG_PARAM_DECL)
	{
		__CGX86_ASSERT((r >= REG_EAX) && (r <= REG_R15D), "Bad 32-bit register");
		return (uint8_t)(r - REG_EAX);
	}

	static __inline uint8_t __alwaysinline __reg64_64bit(OperandType r  __REG_DEBUG_PARAM_DECL)
	{
		__CGX86_ASSERT((r >= REG_RAX) && (r <= REG_R15), "Bad 64-bit register");
		return (uint8_t)(r - REG_RAX);
	}

	static __inline uint8_t __alwaysinline __xmm_32bit(OperandType r  __REG_DEBUG_PARAM_DECL)
	{
		__CGX86_ASSERT((r >= REG_XMM0) && (r <= REG_XMM7), "Bad XMM register");
		return (uint8_t)(r - REG_XMM0);
	}

	static __inline uint8_t __alwaysinline __xmm_64bit(OperandType r  __REG_DEBUG_PARAM_DECL)
	{
		__CGX86_ASSERT((r >= REG_XMM0) && (r <= REG_XMM15), "Bad XMM register");
		return (uint8_t)(r - REG_XMM0);
	}


	// Prefix routines
	static __inline void __alwaysinline __segprefix(uint8_t* buf, int wr, OperandType s)
	{
		if (s == REG_ES)
			__WRITE_BUF_8(0, 0x26);
		else if (s == REG_CS)
			__WRITE_BUF_8(0, 0x2e);
		else if (s == REG_SS)
			__WRITE_BUF_8(0, 0x36);
		else if (s == REG_DS)
			__WRITE_BUF_8(0, 0x3e);
		else if (s == REG_FS)
			__WRITE_BUF_8(0, 0x64);
		else // GS
			__WRITE_BUF_8(0, 0x65);
	}


	// Executable pointer translation helpers
#define __EXEC_OFFSET(n) __translate_to_exec(__CONTEXT_OFFSET(n))

	static __inline const void* __alwaysinline __translate_to_exec(__CONTEXT_PARAMS)
	{
		const void* translatedPtr = buf;
		__NO_ASSERT
		(void)wr;
		if (translate)
			translatedPtr = translate(buf, param);
		return translatedPtr;
	}


	// Simple opcode handling routines
#define __ONEBYTE_INSTR(n, op) __DEF_INSTR_0(n) { return __onebyte(__CONTEXT, op); }
#define __ONEBYTE_OPSZ_INSTR(n, op) __DEF_INSTR_0(n) { return __onebyte_opsz(__CONTEXT, op); }
#define __TWOBYTE_INSTR(n, op) __DEF_INSTR_0(n) { return __twobyte(__CONTEXT, op); }
#define __TWOBYTE_OPSZ_INSTR(n, op) __DEF_INSTR_0(n) { return __twobyte_opsz(__CONTEXT, op); }
#define __ONEBYTE_INSTR_64(n, op) __DEF_INSTR_0(n) { return __onebyte64(__CONTEXT, op); }
#define __TWOBYTE_INSTR_64(n, op) __DEF_INSTR_0(n) { return __twobyte64(__CONTEXT, op); }
#define __FPU_TWOBYTE_INSTR(n, op1, op2) __DEF_INSTR_0(n) { return __fpu_twobyte(__CONTEXT, op1, op2); }

	static __inline size_t __alwaysinline __onebyte(__CONTEXT_PARAMS, uint8_t op)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8(0, op);
		return 1;
	}

	static __inline size_t __alwaysinline __onebyte_opreg_32bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8(0, op + reg);
		return 1;
	}

	static __inline size_t __alwaysinline __onebyte_opreg_64bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		// Must use >= 8 here instead of & 8, see __reg8_64bit function
		if (reg >= 8)
		{
			__WRITE_BUF_8_8(0, __REX(__REX_OPCODE(reg)), op + (reg & 7));
			return 2;
		}
		else
		{
			__WRITE_BUF_8(0, op + reg);
			return 1;
		}
	}

	static __inline size_t __alwaysinline __onebyte64_opreg(__CONTEXT_PARAMS, uint8_t op, uint8_t reg)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		// Must use >= 8 here instead of & 8, see __reg8_64bit function
		if (reg >= 8)
		{
			__WRITE_BUF_8_8(0, __REX(__REX_64 | __REX_OPCODE(reg)), op + (reg & 7));
			return 2;
		}
		else
		{
			__WRITE_BUF_8_8(0, __REX(__REX_64), op + reg);
			return 2;
		}
	}

	static __inline size_t __alwaysinline __onebyte_opsz(__CONTEXT_PARAMS, uint8_t op)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, 0x66, op);
		return 2;
	}

	static __inline size_t __alwaysinline __onebyte_imm8(__CONTEXT_PARAMS, uint8_t op, int8_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, op, imm);
		return 2;
	}

	static __inline size_t __alwaysinline __onebyte_opreg_imm8_32bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg, int8_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, op + reg, imm);
		return 2;
	}

	static __inline size_t __alwaysinline __onebyte_opreg_imm8_64bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg, int8_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		// Must use >= 8 here instead of & 8, see __reg8_64bit function
		if (reg >= 8)
		{
			__WRITE_BUF_8_8(0, __REX(__REX_OPCODE(reg)), op + (reg & 7));
			__WRITE_BUF_8(2, imm);
			return 3;
		}
		else
		{
			__WRITE_BUF_8_8(0, op + reg, imm);
			return 2;
		}
	}

	static __inline size_t __alwaysinline __onebyte_imm16(__CONTEXT_PARAMS, uint8_t op, int16_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8(0, op);
		__WRITE_BUF_16(1, imm);
		return 3;
	}

	static __inline size_t __alwaysinline __onebyte_imm32(__CONTEXT_PARAMS, uint8_t op, int32_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8(0, op);
		__WRITE_BUF_32(1, imm);
		return 5;
	}

	static __inline size_t __alwaysinline __onebyte_opreg_imm32_32bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg, int32_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8(0, op + reg);
		__WRITE_BUF_32(1, imm);
		return 5;
	}

	static __inline size_t __alwaysinline __onebyte_opreg_imm32_64bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg, int32_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		if (reg >= 8)
		{
			__WRITE_BUF_8_8(0, __REX(__REX_OPCODE(reg)), op + (reg & 7));
			__WRITE_BUF_32(2, imm);
			return 6;
		}
		else
		{
			__WRITE_BUF_8(0, op + reg);
			__WRITE_BUF_32(1, imm);
			return 5;
		}
	}

	static __inline size_t __alwaysinline __onebyte_imm64(__CONTEXT_PARAMS, uint8_t op, int64_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8(0, op);
		__WRITE_BUF_64(1, imm);
		return 9;
	}

	static __inline size_t __alwaysinline __onebyte64_opreg_imm64(__CONTEXT_PARAMS, uint8_t op, uint8_t reg, int64_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, __REX(__REX_OPCODE(reg)) | __REX_64, op + (reg & 7));
		__WRITE_BUF_64(2, imm);
		return 10;
	}

	static __inline size_t __alwaysinline __onebyte_opsz_imm8(__CONTEXT_PARAMS, uint8_t op, int8_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, 0x66, op);
		__WRITE_BUF_8(2, imm);
		return 3;
	}

	static __inline size_t __alwaysinline __onebyte_opsz_imm16(__CONTEXT_PARAMS, uint8_t op, int16_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, 0x66, op);
		__WRITE_BUF_16(2, imm);
		return 4;
	}

	static __inline size_t __alwaysinline __onebyte_opreg_opsz_32bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, 0x66, op + reg);
		return 2;
	}

	static __inline size_t __alwaysinline __onebyte_opreg_opsz_64bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		if (reg >= 8)
		{
			__WRITE_BUF_8_8(0, 0x66, __REX(__REX_OPCODE(reg)));
			__WRITE_BUF_8(2, op + (reg & 7));
			return 3;
		}
		else
		{
			__WRITE_BUF_8_8(0, 0x66, op + reg);
			return 2;
		}
	}

	static __inline size_t __alwaysinline __onebyte_opreg_opsz_imm16_32bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg, int16_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, 0x66, op + reg);
		__WRITE_BUF_16(2, imm);
		return 4;
	}

	static __inline size_t __alwaysinline __onebyte_opreg_opsz_imm16_64bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg, int16_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		if (reg >= 8)
		{
			__WRITE_BUF_8_8(0, 0x66, __REX(__REX_OPCODE(reg)));
			__WRITE_BUF_8(2, op + (reg & 7));
			__WRITE_BUF_16(3, imm);
			return 5;
		}
		else
		{
			__WRITE_BUF_8_8(0, 0x66, op + reg);
			__WRITE_BUF_16(2, imm);
			return 4;
		}
	}

	static __inline size_t __alwaysinline __onebyte_opsz_imm32(__CONTEXT_PARAMS, uint8_t op, int32_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, 0x66, op);
		__WRITE_BUF_32(2, imm);
		return 6;
	}

	static __inline size_t __alwaysinline __twobyte(__CONTEXT_PARAMS, uint8_t op)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, 0x0f, op);
		return 2;
	}

	static __inline size_t __alwaysinline __fpu_twobyte(__CONTEXT_PARAMS, uint8_t op1, uint8_t op2)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, op1, op2);
		return 2;
	}

	static __inline size_t __alwaysinline __twobyte_opreg_32bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, 0x0f, op + reg);
		return 2;
	}

	static __inline size_t __alwaysinline __twobyte_opreg_64bit(__CONTEXT_PARAMS, uint8_t op, uint8_t reg)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		// Must use >= 8 here instead of & 8, see __reg8_64bit function
		if (reg >= 8)
		{
			__WRITE_BUF_8_8(0, __REX(__REX_OPCODE(reg)), 0x0f);
			__WRITE_BUF_8(2, op + (reg & 7));
			return 3;
		}
		else
		{
			__WRITE_BUF_8_8(0, 0x0f, op + reg);
			return 2;
		}
	}

	static __inline size_t __alwaysinline __onebyte64(__CONTEXT_PARAMS, uint8_t op)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, __REX(__REX_64), op);
		return 2;
	}

	static __inline size_t __alwaysinline __onebyte64_imm8(__CONTEXT_PARAMS, uint8_t op, int8_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, __REX(__REX_64), op);
		__WRITE_BUF_8(2, imm);
		return 3;
	}

	static __inline size_t __alwaysinline __onebyte64_imm32(__CONTEXT_PARAMS, uint8_t op, int32_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, __REX(__REX_64), op);
		__WRITE_BUF_32(2, imm);
		return 6;
	}

	static __inline size_t __alwaysinline __onebyte64_imm64(__CONTEXT_PARAMS, uint8_t op, int64_t imm)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, __REX(__REX_64), op);
		__WRITE_BUF_64(2, imm);
		return 10;
	}

	static __inline size_t __alwaysinline __twobyte64(__CONTEXT_PARAMS, uint8_t op)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, __REX(__REX_64), 0x0f);
		__WRITE_BUF_8(2, op);
		return 3;
	}

	static __inline size_t __alwaysinline __twobyte64_opreg(__CONTEXT_PARAMS, uint8_t op, uint8_t reg)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8_8(0, __REX(__REX_64 | __REX_OPCODE(reg)), 0x0f);
		__WRITE_BUF_8(2, op + (reg & 7));
		return 3;
	}

#endif // __CODEGENX86_COMMON


// Pick optimal form of some of the above functions to avoid REX processing on 32-bit
#ifdef __reg8
#undef __reg8
#endif
#ifdef __reg16
#undef __reg16
#endif
#ifdef __reg32
#undef __reg32
#endif
#ifdef __reg64
#undef __reg64
#endif
#ifdef __xmmreg
#undef __xmmreg
#endif
#ifdef __onebyte_opreg
#undef __onebyte_opreg
#endif
#ifdef __onebyte_opreg_imm8
#undef __onebyte_opreg_imm8
#endif
#ifdef __onebyte_opreg_imm32
#undef __onebyte_opreg_imm32
#endif
#ifdef __onebyte_opreg_opsz
#undef __onebyte_opreg_opsz
#endif
#ifdef __onebyte_opreg_opsz_imm16
#undef __onebyte_opreg_opsz_imm16
#endif
#ifdef __twobyte_opreg
#undef __twobyte_opreg
#endif
#ifdef __CODEGENX86_32BIT
#define __reg8(r) __reg8_32bit(r __REG_DEBUG_PARAMS)
#define __reg16(r) __reg16_32bit(r __REG_DEBUG_PARAMS)
#define __reg32(r) __reg32_32bit(r __REG_DEBUG_PARAMS)
#define __xmmreg(r) __xmm_32bit(r __REG_DEBUG_PARAMS)
#define __onebyte_opreg __onebyte_opreg_32bit
#define __onebyte_opreg_imm8 __onebyte_opreg_imm8_32bit
#define __onebyte_opreg_imm32 __onebyte_opreg_imm32_32bit
#define __onebyte_opreg_opsz __onebyte_opreg_opsz_32bit
#define __onebyte_opreg_opsz_imm16 __onebyte_opreg_opsz_imm16_32bit
#define __twobyte_opreg __twobyte_opreg_32bit
#else
#define __reg8(r) __reg8_64bit(r __REG_DEBUG_PARAMS)
#define __reg16(r) __reg16_64bit(r __REG_DEBUG_PARAMS)
#define __reg32(r) __reg32_64bit(r __REG_DEBUG_PARAMS)
#define __reg64(r) __reg64_64bit(r __REG_DEBUG_PARAMS)
#define __xmmreg(r) __xmm_64bit(r __REG_DEBUG_PARAMS)
#define __onebyte_opreg __onebyte_opreg_64bit
#define __onebyte_opreg_imm8 __onebyte_opreg_imm8_64bit
#define __onebyte_opreg_imm32 __onebyte_opreg_imm32_64bit
#define __onebyte_opreg_opsz __onebyte_opreg_opsz_64bit
#define __onebyte_opreg_opsz_imm16 __onebyte_opreg_opsz_imm16_64bit
#define __twobyte_opreg __twobyte_opreg_64bit
#endif


// Name generators
#ifdef __PREFIX
#undef __PREFIX
#endif
#ifdef __NAME
#undef __NAME
#endif
#ifdef __CODEGENX86_32BIT
#define __PREFIX(n) __cgx86_32_ ## n
#define __NAME(n, t) __cgx86_32_ ## n ## _ ## t
#define __PREFIX32(n) __cgx86_32_ ## n
#define __NAME32(n, t) __cgx86_32_ ## n ## _ ## t
#else
#define __PREFIX(n) __cgx86_64_ ## n
#define __NAME(n, t) __cgx86_64_ ## n ## _ ## t
#define __PREFIX64(n) __cgx86_64_ ## n
#define __NAME64(n, t) __cgx86_64_ ## n ## _ ## t
#endif


// Emit macros
#ifdef __CODEGENX86_32BIT

#define X86_EMIT32(buf, op) __PREFIX32(op) (__EMIT_CONTEXT(buf))
#define X86_EMIT32_R(buf, op, a) __NAME32(op, r) (__EMIT_CONTEXT(buf), a)
#define X86_EMIT32_M(buf, op, a) __NAME32(op, m) (__EMIT_CONTEXT(buf), X86_MEM_PARAM(a))
#define X86_EMIT32_I(buf, op, a) __NAME32(op, i) (__EMIT_CONTEXT(buf), a)
#define X86_EMIT32_II(buf, op, a, b) __NAME32(op, ii) (__EMIT_CONTEXT(buf), a, b)
#define X86_EMIT32_P(buf, op, a) __NAME32(op, p) (__EMIT_CONTEXT(buf), a)
#define X86_EMIT32_T(buf, op, a) __NAME32(op, t) (__EMIT_CONTEXT(buf), &a)
#define X86_EMIT32_RR(buf, op, a, b) __NAME32(op, rr) (__EMIT_CONTEXT(buf), a, b)
#define X86_EMIT32_RM(buf, op, a, b) __NAME32(op, rm) (__EMIT_CONTEXT(buf), a, X86_MEM_PARAM(b))
#define X86_EMIT32_MR(buf, op, a, b) __NAME32(op, mr) (__EMIT_CONTEXT(buf), X86_MEM_PARAM(a), b)
#define X86_EMIT32_RI(buf, op, a, b) __NAME32(op, ri) (__EMIT_CONTEXT(buf), a, b)
#define X86_EMIT32_MI(buf, op, a, b) __NAME32(op, mi) (__EMIT_CONTEXT(buf), X86_MEM_PARAM(a), b)
#define X86_EMIT32_RRR(buf, op, a, b, c) __NAME32(op, rrr) (__EMIT_CONTEXT(buf), a, b, c)
#define X86_EMIT32_RRI(buf, op, a, b, c) __NAME32(op, rri) (__EMIT_CONTEXT(buf), a, b, c)
#define X86_EMIT32_RMI(buf, op, a, b, c) __NAME32(op, rmi) (__EMIT_CONTEXT(buf), a, X86_MEM_PARAM(b), c)
#define X86_EMIT32_MRR(buf, op, a, b, c) __NAME32(op, mrr) (__EMIT_CONTEXT(buf), X86_MEM_PARAM(a), b, c)
#define X86_EMIT32_MRI(buf, op, a, b, c) __NAME32(op, mri) (__EMIT_CONTEXT(buf), X86_MEM_PARAM(a), b, c)
#define X86_EMIT32_SEG(buf, op, seg) __SEGPREFIX(buf, 1, seg, __PREFIX32(op) (__EMIT_CONTEXT_OFFSET(buf, 1)))
#define X86_EMIT32_SEG_M(buf, op, seg, a) __SEGPREFIX(buf, 1, seg, __NAME32(op, m) (__EMIT_CONTEXT_OFFSET(buf, 1), X86_MEM_PARAM(a)))
#define X86_EMIT32_SEG_RM(buf, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME32(op, rm) (__EMIT_CONTEXT_OFFSET(buf, 1), a, X86_MEM_PARAM(b)))
#define X86_EMIT32_SEG_MR(buf, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME32(op, mr) (__EMIT_CONTEXT_OFFSET(buf, 1), X86_MEM_PARAM(a), b))
#define X86_EMIT32_SEG_MI(buf, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME32(op, mi) (__EMIT_CONTEXT_OFFSET(buf, 1), X86_MEM_PARAM(a), b))
#define X86_EMIT32_SEG_RMI(buf, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME32(op, rmi) (__EMIT_CONTEXT_OFFSET(buf, 1), a, X86_MEM_PARAM(b), c))
#define X86_EMIT32_SEG_MRR(buf, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME32(op, mrr) (__EMIT_CONTEXT_OFFSET(buf, 1), X86_MEM_PARAM(a), b, c))
#define X86_EMIT32_SEG_MRI(buf, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME32(op, mri) (__EMIT_CONTEXT_OFFSET(buf, 1), X86_MEM_PARAM(a), b, c))

#define X86_ALTEXEC_EMIT32(buf, xlat, param, op) __PREFIX32(op) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param))
#define X86_ALTEXEC_EMIT32_R(buf, xlat, param, op, a) __NAME32(op, r) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a)
#define X86_ALTEXEC_EMIT32_M(buf, xlat, param, op, a) __NAME32(op, m) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), X86_MEM_PARAM(a))
#define X86_ALTEXEC_EMIT32_I(buf, xlat, param, op, a) __NAME32(op, i) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a)
#define X86_ALTEXEC_EMIT32_II(buf, xlat, param, op, a, b) __NAME32(op, ii) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, b)
#define X86_ALTEXEC_EMIT32_P(buf, xlat, param, op, a) __NAME32(op, p) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a)
#define X86_ALTEXEC_EMIT32_T(buf, xlat, param, op, a) __NAME32(op, t) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), &a)
#define X86_ALTEXEC_EMIT32_RR(buf, xlat, param, op, a, b) __NAME32(op, rr) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, b)
#define X86_ALTEXEC_EMIT32_RM(buf, xlat, param, op, a, b) __NAME32(op, rm) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, X86_MEM_PARAM(b))
#define X86_ALTEXEC_EMIT32_MR(buf, xlat, param, op, a, b) __NAME32(op, mr) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), X86_MEM_PARAM(a), b)
#define X86_ALTEXEC_EMIT32_RI(buf, xlat, param, op, a, b) __NAME32(op, ri) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, b)
#define X86_ALTEXEC_EMIT32_MI(buf, xlat, param, op, a, b) __NAME32(op, mi) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), X86_MEM_PARAM(a), b)
#define X86_ALTEXEC_EMIT32_RRR(buf, xlat, param, op, a, b, c) __NAME32(op, rrr) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, b, c)
#define X86_ALTEXEC_EMIT32_RRI(buf, xlat, param, op, a, b, c) __NAME32(op, rri) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, b, c)
#define X86_ALTEXEC_EMIT32_RMI(buf, xlat, param, op, a, b, c) __NAME32(op, rmi) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, X86_MEM_PARAM(b), c)
#define X86_ALTEXEC_EMIT32_MRR(buf, xlat, param, op, a, b, c) __NAME32(op, mrr) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), X86_MEM_PARAM(a), b, c)
#define X86_ALTEXEC_EMIT32_MRI(buf, xlat, param, op, a, b, c) __NAME32(op, mri) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), X86_MEM_PARAM(a), b, c)
#define X86_ALTEXEC_EMIT32_SEG(buf, xlat, param, op, seg) __SEGPREFIX(buf, 1, seg, __PREFIX32(op) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1)))
#define X86_ALTEXEC_EMIT32_SEG_M(buf, xlat, param, op, seg, a) __SEGPREFIX(buf, 1, seg, __NAME32(op, m) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), X86_MEM_PARAM(a)))
#define X86_ALTEXEC_EMIT32_SEG_RM(buf, xlat, param, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME32(op, rm) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), a, X86_MEM_PARAM(b)))
#define X86_ALTEXEC_EMIT32_SEG_MR(buf, xlat, param, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME32(op, mr) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), X86_MEM_PARAM(a), b))
#define X86_ALTEXEC_EMIT32_SEG_MI(buf, xlat, param, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME32(op, mi) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), X86_MEM_PARAM(a), b))
#define X86_ALTEXEC_EMIT32_SEG_RMI(buf, xlat, param, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME32(op, rmi) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), a, X86_MEM_PARAM(b), c))
#define X86_ALTEXEC_EMIT32_SEG_MRR(buf, xlat, param, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME32(op, mrr) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), X86_MEM_PARAM(a), b, c))
#define X86_ALTEXEC_EMIT32_SEG_MRI(buf, xlat, param, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME32(op, mri) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), X86_MEM_PARAM(a), b, c))

#define X86_LENGTH32(op) __PREFIX32(op) (__LENGTH_CONTEXT)
#define X86_LENGTH32_R(op, a) __NAME32(op, r) (__LENGTH_CONTEXT, a)
#define X86_LENGTH32_M(op, a) __NAME32(op, m) (__LENGTH_CONTEXT, X86_MEM_PARAM(a))
#define X86_LENGTH32_I(op, a) __NAME32(op, i) (__LENGTH_CONTEXT, a)
#define X86_LENGTH32_II(op, a, b) __NAME32(op, ii) (__LENGTH_CONTEXT, a, b)
#define X86_LENGTH32_P(op, a) __NAME32(op, p) (__LENGTH_CONTEXT, a)
#define X86_LENGTH32_T(op, a) __NAME32(op, t) (__LENGTH_CONTEXT, &a)
#define X86_LENGTH32_RR(op, a, b) __NAME32(op, rr) (__LENGTH_CONTEXT, a, b)
#define X86_LENGTH32_RM(op, a, b) __NAME32(op, rm) (__LENGTH_CONTEXT, a, X86_MEM_PARAM(b))
#define X86_LENGTH32_MR(op, a, b) __NAME32(op, mr) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b)
#define X86_LENGTH32_RI(op, a, b) __NAME32(op, ri) (__LENGTH_CONTEXT, a, b)
#define X86_LENGTH32_MI(op, a, b) __NAME32(op, mi) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b)
#define X86_LENGTH32_RRR(op, a, b, c) __NAME32(op, rrr) (__LENGTH_CONTEXT, a, b, c)
#define X86_LENGTH32_RRI(op, a, b, c) __NAME32(op, rri) (__LENGTH_CONTEXT, a, b, c)
#define X86_LENGTH32_RMI(op, a, b, c) __NAME32(op, rmi) (__LENGTH_CONTEXT, a, X86_MEM_PARAM(b), c)
#define X86_LENGTH32_MRR(op, a, b, c) __NAME32(op, mrr) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b, c)
#define X86_LENGTH32_MRI(op, a, b, c) __NAME32(op, mri) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b, c)
#define X86_LENGTH32_SEG(op, seg) __SEGPREFIX(0, 0, seg, __PREFIX32(op) (__LENGTH_CONTEXT))
#define X86_LENGTH32_SEG_M(op, seg, a) __SEGPREFIX(0, 0, seg, __NAME32(op, m) (__LENGTH_CONTEXT, X86_MEM_PARAM(a)))
#define X86_LENGTH32_SEG_RM(op, seg, a, b) __SEGPREFIX(0, 0, seg, __NAME32(op, rm) (__LENGTH_CONTEXT, a, X86_MEM_PARAM(b)))
#define X86_LENGTH32_SEG_MR(op, seg, a, b) __SEGPREFIX(0, 0, seg, __NAME32(op, mr) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b))
#define X86_LENGTH32_SEG_MI(op, seg, a, b) __SEGPREFIX(0, 0, seg, __NAME32(op, mi) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b))
#define X86_LENGTH32_SEG_RMI(op, seg, a, b, c) __SEGPREFIX(0, 0, seg, __NAME32(op, rmi) (__LENGTH_CONTEXT, a, X86_MEM_PARAM(b), c))
#define X86_LENGTH32_SEG_MRR(op, seg, a, b, c) __SEGPREFIX(0, 0, seg, __NAME32(op, mrr) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b, c))
#define X86_LENGTH32_SEG_MRI(op, seg, a, b, c) __SEGPREFIX(0, 0, seg, __NAME32(op, mri) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b, c))

#define X86_DYNALLOC_EMIT32(buf, alloc, adv, op) adv(buf, X86_EMIT32(alloc(buf, X86_LENGTH32(op)), op))
#define X86_DYNALLOC_EMIT32_R(buf, alloc, adv, op, a) adv(buf, X86_EMIT32_R(alloc(buf, X86_LENGTH32_R(op, a)), op, a))
#define X86_DYNALLOC_EMIT32_M(buf, alloc, adv, op, a) adv(buf, X86_EMIT32_M(alloc(buf, X86_LENGTH32_M(op, X86_MEM_PARAM(a))), op, X86_MEM_PARAM(a)))
#define X86_DYNALLOC_EMIT32_I(buf, alloc, adv, op, a) adv(buf, X86_EMIT32_I(alloc(buf, X86_LENGTH32_I(op, a)), op, a))
#define X86_DYNALLOC_EMIT32_II(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT32_II(alloc(buf, X86_LENGTH32_II(op, a, b)), op, a, b))
#define X86_DYNALLOC_EMIT32_P(buf, alloc, adv, op, a) adv(buf, X86_EMIT32_P(alloc(buf, X86_LENGTH32_P(op, a)), op, a))
#define X86_DYNALLOC_EMIT32_T(buf, alloc, adv, op, a) adv(buf, X86_EMIT32_T(alloc(buf, X86_LENGTH32_T(op, a)), op, a))
#define X86_DYNALLOC_EMIT32_RR(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT32_RR(alloc(buf, X86_LENGTH32_RR(op, a, b)), op, a, b))
#define X86_DYNALLOC_EMIT32_RM(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT32_RM(alloc(buf, X86_LENGTH32_RM(op, a, X86_MEM_PARAM(b))), op, a, X86_MEM_PARAM(b)))
#define X86_DYNALLOC_EMIT32_MR(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT32_MR(alloc(buf, X86_LENGTH32_MR(op, X86_MEM_PARAM(a), b)), op, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_EMIT32_RI(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT32_RI(alloc(buf, X86_LENGTH32_RI(op, a, b)), op, a, b))
#define X86_DYNALLOC_EMIT32_MI(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT32_MI(alloc(buf, X86_LENGTH32_MI(op, X86_MEM_PARAM(a), b)), op, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_EMIT32_RRR(buf, alloc, adv, op, a, b, c) adv(buf, X86_EMIT32_RRR(alloc(buf, X86_LENGTH32_RRR(op, a, b, c)), op, a, b, c))
#define X86_DYNALLOC_EMIT32_RRI(buf, alloc, adv, op, a, b, c) adv(buf, X86_EMIT32_RRI(alloc(buf, X86_LENGTH32_RRI(op, a, b, c)), op, a, b, c))
#define X86_DYNALLOC_EMIT32_RMI(buf, alloc, adv, op, a, b, c) adv(buf, X86_EMIT32_RMI(alloc(buf, X86_LENGTH32_RMI(op, a, X86_MEM_PARAM(b), c)), op, a, X86_MEM_PARAM(b), c))
#define X86_DYNALLOC_EMIT32_MRR(buf, alloc, adv, op, a, b, c) adv(buf, X86_EMIT32_MRR(alloc(buf, X86_LENGTH32_MRR(op, X86_MEM_PARAM(a), b, c)), op, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_EMIT32_MRI(buf, alloc, adv, op, a, b, c) adv(buf, X86_EMIT32_MRI(alloc(buf, X86_LENGTH32_MRI(op, X86_MEM_PARAM(a), b, c)), op, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_EMIT32_SEG(buf, alloc, adv, op, seg) adv(buf, X86_EMIT32_SEG(alloc(buf, X86_LENGTH32_SEG(op, seg)), op, seg))
#define X86_DYNALLOC_EMIT32_SEG_M(buf, alloc, adv, op, seg, a) adv(buf, X86_EMIT32_SEG_M(alloc(buf, X86_LENGTH32_SEG_M(op, seg, X86_MEM_PARAM(a))), op, seg, X86_MEM_PARAM(a)))
#define X86_DYNALLOC_EMIT32_SEG_RM(buf, alloc, adv, op, seg, a, b) adv(buf, X86_EMIT32_SEG_RM(alloc(buf, X86_LENGTH32_SEG_RM(op, seg, a, X86_MEM_PARAM(b))), op, seg, a, X86_MEM_PARAM(b)))
#define X86_DYNALLOC_EMIT32_SEG_MR(buf, alloc, adv, op, seg, a, b) adv(buf, X86_EMIT32_SEG_MR(alloc(buf, X86_LENGTH32_SEG_MR(op, seg, X86_MEM_PARAM(a), b)), op, seg, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_EMIT32_SEG_MI(buf, alloc, adv, op, seg, a, b) adv(buf, X86_EMIT32_SEG_MI(alloc(buf, X86_LENGTH32_SEG_MI(op, seg, X86_MEM_PARAM(a), b)), op, seg, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_EMIT32_SEG_RMI(buf, alloc, adv, op, seg, a, b, c) adv(buf, X86_EMIT32_SEG_RMI(alloc(buf, X86_LENGTH32_SEG_RMI(op, seg, a, X86_MEM_PARAM(b), c)), op, seg, a, X86_MEM_PARAM(b), c))
#define X86_DYNALLOC_EMIT32_SEG_MRR(buf, alloc, adv, op, seg, a, b, c) adv(buf, X86_EMIT32_SEG_MRR(alloc(buf, X86_LENGTH32_SEG_MRR(op, seg, X86_MEM_PARAM(a), b, c)), op, seg, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_EMIT32_SEG_MRI(buf, alloc, adv, op, seg, a, b, c) adv(buf, X86_EMIT32_SEG_MRI(alloc(buf, X86_LENGTH32_SEG_MRI(op, seg, X86_MEM_PARAM(a), b, c)), op, seg, X86_MEM_PARAM(a), b, c))

#define X86_DYNALLOC_ALTEXEC_EMIT32(buf, alloc, adv, xlat, param, op) adv(buf, X86_ALTEXEC_EMIT32(alloc(buf, X86_LENGTH32(op)), xlat, param, op))
#define X86_DYNALLOC_ALTEXEC_EMIT32_R(buf, alloc, adv, xlat, param, op, a) adv(buf, X86_ALTEXEC_EMIT32_R(alloc(buf, X86_LENGTH32_R(op, a)), xlat, param, op, a))
#define X86_DYNALLOC_ALTEXEC_EMIT32_M(buf, alloc, adv, xlat, param, op, a) adv(buf, X86_ALTEXEC_EMIT32_M(alloc(buf, X86_LENGTH32_M(op, X86_MEM_PARAM(a))), xlat, param, op, X86_MEM_PARAM(a)))
#define X86_DYNALLOC_ALTEXEC_EMIT32_I(buf, alloc, adv, xlat, param, op, a) adv(buf, X86_ALTEXEC_EMIT32_I(alloc(buf, X86_LENGTH32_I(op, a)), xlat, param, op, a))
#define X86_DYNALLOC_ALTEXEC_EMIT32_II(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT32_II(alloc(buf, X86_LENGTH32_II(op, a, b)), xlat, param, op, a, b))
#define X86_DYNALLOC_ALTEXEC_EMIT32_P(buf, alloc, adv, xlat, param, op, a) adv(buf, X86_ALTEXEC_EMIT32_P(alloc(buf, X86_LENGTH32_P(op, a)), xlat, param, op, a))
#define X86_DYNALLOC_ALTEXEC_EMIT32_T(buf, alloc, adv, xlat, param, op, a) adv(buf, X86_ALTEXEC_EMIT32_T(alloc(buf, X86_LENGTH32_T(op, a)), xlat, param, op, a))
#define X86_DYNALLOC_ALTEXEC_EMIT32_RR(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT32_RR(alloc(buf, X86_LENGTH32_RR(op, a, b)), xlat, param, op, a, b))
#define X86_DYNALLOC_ALTEXEC_EMIT32_RM(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT32_RM(alloc(buf, X86_LENGTH32_RM(op, a, X86_MEM_PARAM(b))), xlat, param, op, a, X86_MEM_PARAM(b)))
#define X86_DYNALLOC_ALTEXEC_EMIT32_MR(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT32_MR(alloc(buf, X86_LENGTH32_MR(op, X86_MEM_PARAM(a), b)), xlat, param, op, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_ALTEXEC_EMIT32_RI(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT32_RI(alloc(buf, X86_LENGTH32_RI(op, a, b)), xlat, param, op, a, b))
#define X86_DYNALLOC_ALTEXEC_EMIT32_MI(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT32_MI(alloc(buf, X86_LENGTH32_MI(op, X86_MEM_PARAM(a), b)), xlat, param, op, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_ALTEXEC_EMIT32_RRR(buf, alloc, adv, xlat, param, op, a, b, c) adv(buf, X86_ALTEXEC_EMIT32_RRR(alloc(buf, X86_LENGTH32_RRR(op, a, b, c)), xlat, param, op, a, b, c))
#define X86_DYNALLOC_ALTEXEC_EMIT32_RRI(buf, alloc, adv, xlat, param, op, a, b, c) adv(buf, X86_ALTEXEC_EMIT32_RRI(alloc(buf, X86_LENGTH32_RRI(op, a, b, c)), xlat, param, op, a, b, c))
#define X86_DYNALLOC_ALTEXEC_EMIT32_RMI(buf, alloc, adv, xlat, param, op, a, b, c) adv(buf, X86_ALTEXEC_EMIT32_RMI(alloc(buf, X86_LENGTH32_RMI(op, a, X86_MEM_PARAM(b), c)), xlat, param, op, a, X86_MEM_PARAM(b), c))
#define X86_DYNALLOC_ALTEXEC_EMIT32_MRR(buf, alloc, adv, xlat, param, op, a, b, c) adv(buf, X86_ALTEXEC_EMIT32_MRR(alloc(buf, X86_LENGTH32_MRR(op, X86_MEM_PARAM(a), b, c)), xlat, param, op, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_ALTEXEC_EMIT32_MRI(buf, alloc, adv, xlat, param, op, a, b, c) adv(buf, X86_ALTEXEC_EMIT32_MRI(alloc(buf, X86_LENGTH32_MRI(op, X86_MEM_PARAM(a), b, c)), xlat, param, op, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_ALTEXEC_EMIT32_SEG(buf, alloc, adv, xlat, param, op, seg) adv(buf, X86_ALTEXEC_EMIT32_SEG(alloc(buf, X86_LENGTH32_SEG(op, seg)), xlat, param, op, seg))
#define X86_DYNALLOC_ALTEXEC_EMIT32_SEG_M(buf, alloc, adv, xlat, param, op, seg, a) adv(buf, X86_ALTEXEC_EMIT32_SEG_M(alloc(buf, X86_LENGTH32_SEG_M(op, seg, X86_MEM_PARAM(a))), xlat, param, op, seg, X86_MEM_PARAM(a)))
#define X86_DYNALLOC_ALTEXEC_EMIT32_SEG_RM(buf, alloc, adv, xlat, param, op, seg, a, b) adv(buf, X86_ALTEXEC_EMIT32_SEG_RM(alloc(buf, X86_LENGTH32_SEG_RM(op, seg, a, X86_MEM_PARAM(b))), xlat, param, op, seg, a, X86_MEM_PARAM(b)))
#define X86_DYNALLOC_ALTEXEC_EMIT32_SEG_MR(buf, alloc, adv, xlat, param, op, seg, a, b) adv(buf, X86_ALTEXEC_EMIT32_SEG_MR(alloc(buf, X86_LENGTH32_SEG_MR(op, seg, X86_MEM_PARAM(a), b)), xlat, param, op, seg, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_ALTEXEC_EMIT32_SEG_MI(buf, alloc, adv, xlat, param, op, seg, a, b) adv(buf, X86_ALTEXEC_EMIT32_SEG_MI(alloc(buf, X86_LENGTH32_SEG_MI(op, seg, X86_MEM_PARAM(a), b)), xlat, param, op, seg, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_ALTEXEC_EMIT32_SEG_RMI(buf, alloc, adv, xlat, param, op, seg, a, b, c) adv(buf, X86_ALTEXEC_EMIT32_SEG_RMI(alloc(buf, X86_LENGTH32_SEG_RMI(op, seg, a, X86_MEM_PARAM(b), c)), xlat, param, op, seg, a, X86_MEM_PARAM(b), c))
#define X86_DYNALLOC_ALTEXEC_EMIT32_SEG_MRR(buf, alloc, adv, xlat, param, op, seg, a, b, c) adv(buf, X86_ALTEXEC_EMIT32_SEG_MRR(alloc(buf, X86_LENGTH32_SEG_MRR(op, seg, X86_MEM_PARAM(a), b, c)), xlat, param, op, seg, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_ALTEXEC_EMIT32_SEG_MRI(buf, alloc, adv, xlat, param, op, seg, a, b, c) adv(buf, X86_ALTEXEC_EMIT32_SEG_MRI(alloc(buf, X86_LENGTH32_SEG_MRI(op, seg, X86_MEM_PARAM(a), b, c)), xlat, param, op, seg, X86_MEM_PARAM(a), b, c))

#else // __CODEGENX86_64BIT

#define X86_EMIT64(buf, op) __PREFIX64(op) (__EMIT_CONTEXT(buf))
#define X86_EMIT64_R(buf, op, a) __NAME64(op, r) (__EMIT_CONTEXT(buf), a)
#define X86_EMIT64_M(buf, op, a) __NAME64(op, m) (__EMIT_CONTEXT(buf), X86_MEM_PARAM(a))
#define X86_EMIT64_I(buf, op, a) __NAME64(op, i) (__EMIT_CONTEXT(buf), a)
#define X86_EMIT64_II(buf, op, a, b) __NAME64(op, ii) (__EMIT_CONTEXT(buf), a, b)
#define X86_EMIT64_P(buf, op, a) __NAME64(op, p) (__EMIT_CONTEXT(buf), a)
#define X86_EMIT64_T(buf, op, a) __NAME64(op, t) (__EMIT_CONTEXT(buf), &a)
#define X86_EMIT64_RR(buf, op, a, b) __NAME64(op, rr) (__EMIT_CONTEXT(buf), a, b)
#define X86_EMIT64_RM(buf, op, a, b) __NAME64(op, rm) (__EMIT_CONTEXT(buf), a, X86_MEM_PARAM(b))
#define X86_EMIT64_MR(buf, op, a, b) __NAME64(op, mr) (__EMIT_CONTEXT(buf), X86_MEM_PARAM(a), b)
#define X86_EMIT64_RI(buf, op, a, b) __NAME64(op, ri) (__EMIT_CONTEXT(buf), a, b)
#define X86_EMIT64_MI(buf, op, a, b) __NAME64(op, mi) (__EMIT_CONTEXT(buf), X86_MEM_PARAM(a), b)
#define X86_EMIT64_RRR(buf, op, a, b, c) __NAME64(op, rrr) (__EMIT_CONTEXT(buf), a, b, c)
#define X86_EMIT64_RRI(buf, op, a, b, c) __NAME64(op, rri) (__EMIT_CONTEXT(buf), a, b, c)
#define X86_EMIT64_RMI(buf, op, a, b, c) __NAME64(op, rmi) (__EMIT_CONTEXT(buf), a, X86_MEM_PARAM(b), c)
#define X86_EMIT64_MRR(buf, op, a, b, c) __NAME64(op, mrr) (__EMIT_CONTEXT(buf), X86_MEM_PARAM(a), b, c)
#define X86_EMIT64_MRI(buf, op, a, b, c) __NAME64(op, mri) (__EMIT_CONTEXT(buf), X86_MEM_PARAM(a), b, c)
#define X86_EMIT64_SEG(buf, op, seg) __SEGPREFIX(buf, 1, seg, __PREFIX64(op) (__EMIT_CONTEXT_OFFSET(buf, 1)))
#define X86_EMIT64_SEG_M(buf, op, seg, a) __SEGPREFIX(buf, 1, seg, __NAME64(op, m) (__EMIT_CONTEXT_OFFSET(buf, 1), X86_MEM_PARAM(a)))
#define X86_EMIT64_SEG_RM(buf, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME64(op, rm) (__EMIT_CONTEXT_OFFSET(buf, 1), a, X86_MEM_PARAM(b)))
#define X86_EMIT64_SEG_MR(buf, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME64(op, mr) (__EMIT_CONTEXT_OFFSET(buf, 1), X86_MEM_PARAM(a), b))
#define X86_EMIT64_SEG_MI(buf, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME64(op, mi) (__EMIT_CONTEXT_OFFSET(buf, 1), X86_MEM_PARAM(a), b))
#define X86_EMIT64_SEG_RMI(buf, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME64(op, rmi) (__EMIT_CONTEXT_OFFSET(buf, 1), a, X86_MEM_PARAM(b), c))
#define X86_EMIT64_SEG_MRR(buf, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME64(op, mrr) (__EMIT_CONTEXT_OFFSET(buf, 1), X86_MEM_PARAM(a), b, c))
#define X86_EMIT64_SEG_MRI(buf, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME64(op, mri) (__EMIT_CONTEXT_OFFSET(buf, 1), X86_MEM_PARAM(a), b, c))

#define X86_ALTEXEC_EMIT64(buf, xlat, param, op) __PREFIX64(op) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param))
#define X86_ALTEXEC_EMIT64_R(buf, xlat, param, op, a) __NAME64(op, r) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a)
#define X86_ALTEXEC_EMIT64_M(buf, xlat, param, op, a) __NAME64(op, m) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), X86_MEM_PARAM(a))
#define X86_ALTEXEC_EMIT64_I(buf, xlat, param, op, a) __NAME64(op, i) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a)
#define X86_ALTEXEC_EMIT64_II(buf, xlat, param, op, a, b) __NAME64(op, ii) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, b)
#define X86_ALTEXEC_EMIT64_P(buf, xlat, param, op, a) __NAME64(op, p) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a)
#define X86_ALTEXEC_EMIT64_T(buf, xlat, param, op, a) __NAME64(op, t) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), &a)
#define X86_ALTEXEC_EMIT64_RR(buf, xlat, param, op, a, b) __NAME64(op, rr) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, b)
#define X86_ALTEXEC_EMIT64_RM(buf, xlat, param, op, a, b) __NAME64(op, rm) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, X86_MEM_PARAM(b))
#define X86_ALTEXEC_EMIT64_MR(buf, xlat, param, op, a, b) __NAME64(op, mr) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), X86_MEM_PARAM(a), b)
#define X86_ALTEXEC_EMIT64_RI(buf, xlat, param, op, a, b) __NAME64(op, ri) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, b)
#define X86_ALTEXEC_EMIT64_MI(buf, xlat, param, op, a, b) __NAME64(op, mi) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), X86_MEM_PARAM(a), b)
#define X86_ALTEXEC_EMIT64_RRR(buf, xlat, param, op, a, b, c) __NAME64(op, rrr) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, b, c)
#define X86_ALTEXEC_EMIT64_RRI(buf, xlat, param, op, a, b, c) __NAME64(op, rri) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, b, c)
#define X86_ALTEXEC_EMIT64_RMI(buf, xlat, param, op, a, b, c) __NAME64(op, rmi) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), a, X86_MEM_PARAM(b), c)
#define X86_ALTEXEC_EMIT64_MRR(buf, xlat, param, op, a, b, c) __NAME64(op, mrr) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), X86_MEM_PARAM(a), b, c)
#define X86_ALTEXEC_EMIT64_MRI(buf, xlat, param, op, a, b, c) __NAME64(op, mri) (__EMIT_ALTEXEC_CONTEXT(buf, xlat, param), X86_MEM_PARAM(a), b, c)
#define X86_ALTEXEC_EMIT64_SEG(buf, xlat, param, op, seg) __SEGPREFIX(buf, 1, seg, __PREFIX64(op) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1)))
#define X86_ALTEXEC_EMIT64_SEG_M(buf, xlat, param, op, seg, a) __SEGPREFIX(buf, 1, seg, __NAME64(op, m) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), X86_MEM_PARAM(a)))
#define X86_ALTEXEC_EMIT64_SEG_RM(buf, xlat, param, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME64(op, rm) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), a, X86_MEM_PARAM(b)))
#define X86_ALTEXEC_EMIT64_SEG_MR(buf, xlat, param, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME64(op, mr) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), X86_MEM_PARAM(a), b))
#define X86_ALTEXEC_EMIT64_SEG_MI(buf, xlat, param, op, seg, a, b) __SEGPREFIX(buf, 1, seg, __NAME64(op, mi) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), X86_MEM_PARAM(a), b))
#define X86_ALTEXEC_EMIT64_SEG_RMI(buf, xlat, param, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME64(op, rmi) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), a, X86_MEM_PARAM(b), c))
#define X86_ALTEXEC_EMIT64_SEG_MRR(buf, xlat, param, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME64(op, mrr) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), X86_MEM_PARAM(a), b, c))
#define X86_ALTEXEC_EMIT64_SEG_MRI(buf, xlat, param, op, seg, a, b, c) __SEGPREFIX(buf, 1, seg, __NAME64(op, mri) (__EMIT_ALTEXEC_CONTEXT_OFFSET(buf, xlat, param, 1), X86_MEM_PARAM(a), b, c))

#define X86_LENGTH64(op) __PREFIX64(op) (__LENGTH_CONTEXT)
#define X86_LENGTH64_R(op, a) __NAME64(op, r) (__LENGTH_CONTEXT, a)
#define X86_LENGTH64_M(op, a) __NAME64(op, m) (__LENGTH_CONTEXT, X86_MEM_PARAM(a))
#define X86_LENGTH64_I(op, a) __NAME64(op, i) (__LENGTH_CONTEXT, a)
#define X86_LENGTH64_II(op, a, b) __NAME64(op, ii) (__LENGTH_CONTEXT, a, b)
#define X86_LENGTH64_P(op, a) __NAME64(op, p) (__LENGTH_CONTEXT, a)
#define X86_LENGTH64_T(op, a) __NAME64(op, t) (__LENGTH_CONTEXT, &a)
#define X86_LENGTH64_RR(op, a, b) __NAME64(op, rr) (__LENGTH_CONTEXT, a, b)
#define X86_LENGTH64_RM(op, a, b) __NAME64(op, rm) (__LENGTH_CONTEXT, a, X86_MEM_PARAM(b))
#define X86_LENGTH64_MR(op, a, b) __NAME64(op, mr) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b)
#define X86_LENGTH64_RI(op, a, b) __NAME64(op, ri) (__LENGTH_CONTEXT, a, b)
#define X86_LENGTH64_MI(op, a, b) __NAME64(op, mi) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b)
#define X86_LENGTH64_RRR(op, a, b, c) __NAME64(op, rrr) (__LENGTH_CONTEXT, a, b, c)
#define X86_LENGTH64_RRI(op, a, b, c) __NAME64(op, rri) (__LENGTH_CONTEXT, a, b, c)
#define X86_LENGTH64_RMI(op, a, b, c) __NAME64(op, rmi) (__LENGTH_CONTEXT, a, X86_MEM_PARAM(b), c)
#define X86_LENGTH64_MRR(op, a, b, c) __NAME64(op, mrr) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b, c)
#define X86_LENGTH64_MRI(op, a, b, c) __NAME64(op, mri) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b, c)
#define X86_LENGTH64_SEG(op, seg) __SEGPREFIX(0, 0, seg, __PREFIX64(op) (__LENGTH_CONTEXT))
#define X86_LENGTH64_SEG_M(op, seg, a) __SEGPREFIX(0, 0, seg, __NAME64(op, m) (__LENGTH_CONTEXT, X86_MEM_PARAM(a)))
#define X86_LENGTH64_SEG_RM(op, seg, a, b) __SEGPREFIX(0, 0, seg, __NAME64(op, rm) (__LENGTH_CONTEXT, a, X86_MEM_PARAM(b)))
#define X86_LENGTH64_SEG_MR(op, seg, a, b) __SEGPREFIX(0, 0, seg, __NAME64(op, mr) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b))
#define X86_LENGTH64_SEG_MI(op, seg, a, b) __SEGPREFIX(0, 0, seg, __NAME64(op, mi) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b))
#define X86_LENGTH64_SEG_RMI(op, seg, a, b, c) __SEGPREFIX(0, 0, seg, __NAME64(op, rmi) (__LENGTH_CONTEXT, a, X86_MEM_PARAM(b), c))
#define X86_LENGTH64_SEG_MRR(op, seg, a, b, c) __SEGPREFIX(0, 0, seg, __NAME64(op, mrr) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b, c))
#define X86_LENGTH64_SEG_MRI(op, seg, a, b, c) __SEGPREFIX(0, 0, seg, __NAME64(op, mri) (__LENGTH_CONTEXT, X86_MEM_PARAM(a), b, c))

#define X86_DYNALLOC_EMIT64(buf, alloc, adv, op) adv(buf, X86_EMIT64(alloc(buf, X86_LENGTH64(op)), op))
#define X86_DYNALLOC_EMIT64_R(buf, alloc, adv, op, a) adv(buf, X86_EMIT64_R(alloc(buf, X86_LENGTH64_R(op, a)), op, a))
#define X86_DYNALLOC_EMIT64_M(buf, alloc, adv, op, a) adv(buf, X86_EMIT64_M(alloc(buf, X86_LENGTH64_M(op, X86_MEM_PARAM(a))), op, X86_MEM_PARAM(a)))
#define X86_DYNALLOC_EMIT64_I(buf, alloc, adv, op, a) adv(buf, X86_EMIT64_I(alloc(buf, X86_LENGTH64_I(op, a)), op, a))
#define X86_DYNALLOC_EMIT64_II(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT64_II(alloc(buf, X86_LENGTH64_II(op, a, b)), op, a, b))
#define X86_DYNALLOC_EMIT64_P(buf, alloc, adv, op, a) adv(buf, X86_EMIT64_P(alloc(buf, X86_LENGTH64_P(op, a)), op, a))
#define X86_DYNALLOC_EMIT64_T(buf, alloc, adv, op, a) adv(buf, X86_EMIT64_T(alloc(buf, X86_LENGTH64_T(op, a)), op, a))
#define X86_DYNALLOC_EMIT64_RR(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT64_RR(alloc(buf, X86_LENGTH64_RR(op, a, b)), op, a, b))
#define X86_DYNALLOC_EMIT64_RM(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT64_RM(alloc(buf, X86_LENGTH64_RM(op, a, X86_MEM_PARAM(b))), op, a, X86_MEM_PARAM(b)))
#define X86_DYNALLOC_EMIT64_MR(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT64_MR(alloc(buf, X86_LENGTH64_MR(op, X86_MEM_PARAM(a), b)), op, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_EMIT64_RI(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT64_RI(alloc(buf, X86_LENGTH64_RI(op, a, b)), op, a, b))
#define X86_DYNALLOC_EMIT64_MI(buf, alloc, adv, op, a, b) adv(buf, X86_EMIT64_MI(alloc(buf, X86_LENGTH64_MI(op, X86_MEM_PARAM(a), b)), op, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_EMIT64_RRR(buf, alloc, adv, op, a, b, c) adv(buf, X86_EMIT64_RRR(alloc(buf, X86_LENGTH64_RRR(op, a, b, c)), op, a, b, c))
#define X86_DYNALLOC_EMIT64_RRI(buf, alloc, adv, op, a, b, c) adv(buf, X86_EMIT64_RRI(alloc(buf, X86_LENGTH64_RRI(op, a, b, c)), op, a, b, c))
#define X86_DYNALLOC_EMIT64_RMI(buf, alloc, adv, op, a, b, c) adv(buf, X86_EMIT64_RMI(alloc(buf, X86_LENGTH64_RMI(op, a, X86_MEM_PARAM(b), c)), op, a, X86_MEM_PARAM(b), c))
#define X86_DYNALLOC_EMIT64_MRR(buf, alloc, adv, op, a, b, c) adv(buf, X86_EMIT64_MRR(alloc(buf, X86_LENGTH64_MRR(op, X86_MEM_PARAM(a), b, c)), op, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_EMIT64_MRI(buf, alloc, adv, op, a, b, c) adv(buf, X86_EMIT64_MRI(alloc(buf, X86_LENGTH64_MRI(op, X86_MEM_PARAM(a), b, c)), op, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_EMIT64_SEG(buf, alloc, adv, op, seg) adv(buf, X86_EMIT64_SEG(alloc(buf, X86_LENGTH64_SEG(op, seg)), op, seg))
#define X86_DYNALLOC_EMIT64_SEG_M(buf, alloc, adv, op, seg, a) adv(buf, X86_EMIT64_SEG_M(alloc(buf, X86_LENGTH64_SEG_M(op, seg, X86_MEM_PARAM(a))), op, seg, X86_MEM_PARAM(a)))
#define X86_DYNALLOC_EMIT64_SEG_RM(buf, alloc, adv, op, seg, a, b) adv(buf, X86_EMIT64_SEG_RM(alloc(buf, X86_LENGTH64_SEG_RM(op, seg, a, X86_MEM_PARAM(b))), op, seg, a, X86_MEM_PARAM(b)))
#define X86_DYNALLOC_EMIT64_SEG_MR(buf, alloc, adv, op, seg, a, b) adv(buf, X86_EMIT64_SEG_MR(alloc(buf, X86_LENGTH64_SEG_MR(op, seg, X86_MEM_PARAM(a), b)), op, seg, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_EMIT64_SEG_MI(buf, alloc, adv, op, seg, a, b) adv(buf, X86_EMIT64_SEG_MI(alloc(buf, X86_LENGTH64_SEG_MI(op, seg, X86_MEM_PARAM(a), b)), op, seg, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_EMIT64_SEG_RMI(buf, alloc, adv, op, seg, a, b, c) adv(buf, X86_EMIT64_SEG_RMI(alloc(buf, X86_LENGTH64_SEG_RMI(op, seg, a, X86_MEM_PARAM(b), c)), op, seg, a, X86_MEM_PARAM(b), c))
#define X86_DYNALLOC_EMIT64_SEG_MRR(buf, alloc, adv, op, seg, a, b, c) adv(buf, X86_EMIT64_SEG_MRR(alloc(buf, X86_LENGTH64_SEG_MRR(op, seg, X86_MEM_PARAM(a), b, c)), op, seg, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_EMIT64_SEG_MRI(buf, alloc, adv, op, seg, a, b, c) adv(buf, X86_EMIT64_SEG_MRI(alloc(buf, X86_LENGTH64_SEG_MRI(op, seg, X86_MEM_PARAM(a), b, c)), op, seg, X86_MEM_PARAM(a), b, c))

#define X86_DYNALLOC_ALTEXEC_EMIT64(buf, alloc, adv, xlat, param, op) adv(buf, X86_ALTEXEC_EMIT64(alloc(buf, X86_LENGTH64(op)), xlat, param, op))
#define X86_DYNALLOC_ALTEXEC_EMIT64_R(buf, alloc, adv, xlat, param, op, a) adv(buf, X86_ALTEXEC_EMIT64_R(alloc(buf, X86_LENGTH64_R(op, a)), xlat, param, op, a))
#define X86_DYNALLOC_ALTEXEC_EMIT64_M(buf, alloc, adv, xlat, param, op, a) adv(buf, X86_ALTEXEC_EMIT64_M(alloc(buf, X86_LENGTH64_M(op, X86_MEM_PARAM(a))), xlat, param, op, X86_MEM_PARAM(a)))
#define X86_DYNALLOC_ALTEXEC_EMIT64_I(buf, alloc, adv, xlat, param, op, a) adv(buf, X86_ALTEXEC_EMIT64_I(alloc(buf, X86_LENGTH64_I(op, a)), xlat, param, op, a))
#define X86_DYNALLOC_ALTEXEC_EMIT64_II(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT64_II(alloc(buf, X86_LENGTH64_II(op, a, b)), xlat, param, op, a, b))
#define X86_DYNALLOC_ALTEXEC_EMIT64_P(buf, alloc, adv, xlat, param, op, a) adv(buf, X86_ALTEXEC_EMIT64_P(alloc(buf, X86_LENGTH64_P(op, a)), xlat, param, op, a))
#define X86_DYNALLOC_ALTEXEC_EMIT64_T(buf, alloc, adv, xlat, param, op, a) adv(buf, X86_ALTEXEC_EMIT64_T(alloc(buf, X86_LENGTH64_T(op, a)), xlat, param, op, a))
#define X86_DYNALLOC_ALTEXEC_EMIT64_RR(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT64_RR(alloc(buf, X86_LENGTH64_RR(op, a, b)), xlat, param, op, a, b))
#define X86_DYNALLOC_ALTEXEC_EMIT64_RM(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT64_RM(alloc(buf, X86_LENGTH64_RM(op, a, X86_MEM_PARAM(b))), xlat, param, op, a, X86_MEM_PARAM(b)))
#define X86_DYNALLOC_ALTEXEC_EMIT64_MR(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT64_MR(alloc(buf, X86_LENGTH64_MR(op, X86_MEM_PARAM(a), b)), xlat, param, op, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_ALTEXEC_EMIT64_RI(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT64_RI(alloc(buf, X86_LENGTH64_RI(op, a, b)), xlat, param, op, a, b))
#define X86_DYNALLOC_ALTEXEC_EMIT64_MI(buf, alloc, adv, xlat, param, op, a, b) adv(buf, X86_ALTEXEC_EMIT64_MI(alloc(buf, X86_LENGTH64_MI(op, X86_MEM_PARAM(a), b)), xlat, param, op, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_ALTEXEC_EMIT64_RRR(buf, alloc, adv, xlat, param, op, a, b, c) adv(buf, X86_ALTEXEC_EMIT64_RRR(alloc(buf, X86_LENGTH64_RRR(op, a, b, c)), xlat, param, op, a, b, c))
#define X86_DYNALLOC_ALTEXEC_EMIT64_RRI(buf, alloc, adv, xlat, param, op, a, b, c) adv(buf, X86_ALTEXEC_EMIT64_RRI(alloc(buf, X86_LENGTH64_RRI(op, a, b, c)), xlat, param, op, a, b, c))
#define X86_DYNALLOC_ALTEXEC_EMIT64_RMI(buf, alloc, adv, xlat, param, op, a, b, c) adv(buf, X86_ALTEXEC_EMIT64_RMI(alloc(buf, X86_LENGTH64_RMI(op, a, X86_MEM_PARAM(b), c)), xlat, param, op, a, X86_MEM_PARAM(b), c))
#define X86_DYNALLOC_ALTEXEC_EMIT64_MRR(buf, alloc, adv, xlat, param, op, a, b, c) adv(buf, X86_ALTEXEC_EMIT64_MRR(alloc(buf, X86_LENGTH64_MRR(op, X86_MEM_PARAM(a), b, c)), xlat, param, op, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_ALTEXEC_EMIT64_MRI(buf, alloc, adv, xlat, param, op, a, b, c) adv(buf, X86_ALTEXEC_EMIT64_MRI(alloc(buf, X86_LENGTH64_MRI(op, X86_MEM_PARAM(a), b, c)), xlat, param, op, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_ALTEXEC_EMIT64_SEG(buf, alloc, adv, xlat, param, op, seg) adv(buf, X86_ALTEXEC_EMIT64_SEG(alloc(buf, X86_LENGTH64_SEG(op, seg)), xlat, param, op, seg))
#define X86_DYNALLOC_ALTEXEC_EMIT64_SEG_M(buf, alloc, adv, xlat, param, op, seg, a) adv(buf, X86_ALTEXEC_EMIT64_SEG_M(alloc(buf, X86_LENGTH64_SEG_M(op, seg, X86_MEM_PARAM(a))), xlat, param, op, seg, X86_MEM_PARAM(a)))
#define X86_DYNALLOC_ALTEXEC_EMIT64_SEG_RM(buf, alloc, adv, xlat, param, op, seg, a, b) adv(buf, X86_ALTEXEC_EMIT64_SEG_RM(alloc(buf, X86_LENGTH64_SEG_RM(op, seg, a, X86_MEM_PARAM(b))), xlat, param, op, seg, a, X86_MEM_PARAM(b)))
#define X86_DYNALLOC_ALTEXEC_EMIT64_SEG_MR(buf, alloc, adv, xlat, param, op, seg, a, b) adv(buf, X86_ALTEXEC_EMIT64_SEG_MR(alloc(buf, X86_LENGTH64_SEG_MR(op, seg, X86_MEM_PARAM(a), b)), xlat, param, op, seg, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_ALTEXEC_EMIT64_SEG_MI(buf, alloc, adv, xlat, param, op, seg, a, b) adv(buf, X86_ALTEXEC_EMIT64_SEG_MI(alloc(buf, X86_LENGTH64_SEG_MI(op, seg, X86_MEM_PARAM(a), b)), xlat, param, op, seg, X86_MEM_PARAM(a), b))
#define X86_DYNALLOC_ALTEXEC_EMIT64_SEG_RMI(buf, alloc, adv, xlat, param, op, seg, a, b, c) adv(buf, X86_ALTEXEC_EMIT64_SEG_RMI(alloc(buf, X86_LENGTH64_SEG_RMI(op, seg, a, X86_MEM_PARAM(b), c)), xlat, param, op, seg, a, X86_MEM_PARAM(b), c))
#define X86_DYNALLOC_ALTEXEC_EMIT64_SEG_MRR(buf, alloc, adv, xlat, param, op, seg, a, b, c) adv(buf, X86_ALTEXEC_EMIT64_SEG_MRR(alloc(buf, X86_LENGTH64_SEG_MRR(op, seg, X86_MEM_PARAM(a), b, c)), xlat, param, op, seg, X86_MEM_PARAM(a), b, c))
#define X86_DYNALLOC_ALTEXEC_EMIT64_SEG_MRI(buf, alloc, adv, xlat, param, op, seg, a, b, c) adv(buf, X86_ALTEXEC_EMIT64_SEG_MRI(alloc(buf, X86_LENGTH64_SEG_MRI(op, seg, X86_MEM_PARAM(a), b, c)), xlat, param, op, seg, X86_MEM_PARAM(a), b, c))

#endif


	// Jump targets
#ifdef __FORWARD_REF_JUMP_SIZE
#undef __FORWARD_REF_JUMP_SIZE
#endif
#ifdef __FORWARD_REF_COND_JUMP_SIZE
#undef __FORWARD_REF_COND_JUMP_SIZE
#endif
#ifdef __FORWARD_REF_JCXZ_JUMP_SIZE
#undef __FORWARD_REF_JCXZ_JUMP_SIZE
#endif
#ifdef __CODEGENX86_32BIT

	#define X86_MARK_JUMP_LABEL_32(buf, n) __PREFIX32(mark_label) (buf, 0, 0, &(n)  __CGX86_LOCATION_PARAM)
	#define X86_ALTEXEC_MARK_JUMP_LABEL_32(buf, translate, param, n) __PREFIX32(mark_label) (buf, translate, param, &(n)  __CGX86_LOCATION_PARAM)
	#define __FORWARD_REF_JUMP_SIZE 5
	#define __FORWARD_REF_COND_JUMP_SIZE 6
	#define __FORWARD_REF_NEAR_JUMP_SIZE 5
	#define __FORWARD_REF_COND_NEAR_JUMP_SIZE 6
	#define __FORWARD_REF_JCXZ_JUMP_SIZE 10
	#define __FORWARD_REF_JCXZ_NEAR_JUMP_SIZE 10

	static __inline void __PREFIX(mark_label) (uint8_t* buf, const void* (*translate)(const void* ptr, void* param), void* param, JumpLabel* target  __CGX86_ASSERT_PARAM_DECL)
	{
		while (target->chain)
		{
			uint8_t* next = (uint8_t*)(size_t)*(uint32_t*)target->chain;
			__JumpTargetType type = (__JumpTargetType)target->chain[4];
			const void* translatedPtr = target->chain;
			if (translate)
				translatedPtr = translate(target->chain, param);
			if (type == __JUMPTARGET_ALWAYS)
			{
				target->chain[0] = 0xe9;
				*((uint32_t*)&target->chain[1]) = (uint32_t)((size_t)buf - ((size_t)translatedPtr + 5));
			}
			else if (type == __JUMPTARGET_JCXZ)
			{
				int64_t diff = (int64_t)((size_t)buf - ((size_t)translatedPtr + 3));
				if ((diff >= -0x80) && (diff <= 0x7f))
				{
					target->chain[0] = 0x67;
					target->chain[1] = 0xe3;
					target->chain[2] = (uint8_t)diff;
					target->chain[3] = 0xeb;
					target->chain[4] = 5;
				}
				else
				{
					target->chain[0] = 0x67;
					target->chain[1] = 0xe3;
					target->chain[2] = 2;
					target->chain[3] = 0xeb;
					target->chain[4] = 5;
					target->chain[5] = 0xe9;
					*((uint32_t*)&target->chain[6]) = (uint32_t)((size_t)buf - ((size_t)translatedPtr + 10));
				}
			}
			else if (type == __JUMPTARGET_JECXZ)
			{
				int64_t diff = (int64_t)((size_t)buf - ((size_t)translatedPtr + 2));
				if ((diff >= -0x80) && (diff <= 0x7f))
				{
					target->chain[0] = 0xe3;
					target->chain[1] = (uint8_t)diff;
					target->chain[2] = 0xeb;
					target->chain[3] = 6;
					target->chain[4] = 0xff;
				}
				else
				{
					target->chain[0] = 0xe3;
					target->chain[1] = 2;
					target->chain[2] = 0xeb;
					target->chain[3] = 6;
					target->chain[4] = 0xe9;
					*((uint32_t*)&target->chain[5]) = (uint32_t)((size_t)buf - ((size_t)translatedPtr + 9));
				}
			}
			else
			{
				target->chain[0] = 0x0f;
				target->chain[1] = (uint8_t)(0x80 + type);
				*((uint32_t*)&target->chain[2]) = (uint32_t)((size_t)buf - ((size_t)translatedPtr + 6));
			}
			target->chain = next;
		}
		target->addr = buf;
	}

	static __inline void __alwaysinline __PREFIX(add_label_ref) (JumpLabel* target, uint8_t* ref, __JumpTargetType type  __CGX86_ASSERT_PARAM_DECL)
	{
		__NO_ASSERT
		*(uint32_t*)ref = (uint32_t)(size_t)target->chain;
		ref[4] = (uint8_t)type;
		if ((type == __JUMPTARGET_JCXZ) || (type == __JUMPTARGET_JECXZ))
		{
			*((uint32_t*)&ref[5]) = 0xcccccccc;
			ref[9] = 0xcc;
		}
		target->chain = ref;
	}

#else // __CODEGENX86_64BIT

	#define X86_MARK_JUMP_LABEL_64(buf, n) __PREFIX64(mark_label) (buf, 0, 0, &(n)  __CGX86_LOCATION_PARAM)
	#define X86_ALTEXEC_MARK_JUMP_LABEL_64(buf, translate, param, n) __PREFIX64(mark_label) (buf, translate, param, &(n)  __CGX86_LOCATION_PARAM)
	#define __FORWARD_REF_JUMP_SIZE 14
	#define __FORWARD_REF_COND_JUMP_SIZE 16
	#define __FORWARD_REF_NEAR_JUMP_SIZE 5
	#define __FORWARD_REF_COND_NEAR_JUMP_SIZE 6
	#define __FORWARD_REF_JCXZ_JUMP_SIZE 19
	#define __FORWARD_REF_JCXZ_NEAR_JUMP_SIZE 10

	static __inline void __PREFIX(mark_label) (uint8_t* buf, const void* (*translate)(const void* ptr, void* param), void* param, JumpLabel* target  __CGX86_ASSERT_PARAM_DECL)
	{
		while (target->chain)
		{
			const void* translatedPtr = target->chain;
			uint8_t* next = 0;
			if (translate)
				translatedPtr = translate(target->chain, param);
			if (target->nearJump)
			{
				int32_t refdiff = *(int32_t*)target->chain;
				__JumpTargetType type = (__JumpTargetType)target->chain[4];
				if (refdiff)
					next = (uint8_t*)target->chain + refdiff;
				if (type == __JUMPTARGET_ALWAYS)
				{
					int64_t diff = (int64_t)((size_t)buf - ((size_t)translatedPtr + 5));
					__CGX86_ASSERT((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL), "Near label out of range");
					target->chain[0] = 0xe9;
					*((int32_t*)&target->chain[1]) = (int32_t)diff;
				}
				else if (type == __JUMPTARGET_JECXZ)
				{
					int64_t diff = (int64_t)((size_t)buf - ((size_t)translatedPtr + 3));
					__CGX86_ASSERT((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL), "Near label out of range");
					if ((diff >= -0x80) && (diff <= 0x7f))
					{
						target->chain[0] = 0x67;
						target->chain[1] = 0xe3;
						target->chain[2] = (uint8_t)diff;
						target->chain[3] = 0xeb;
						target->chain[4] = 5;
					}
					else
					{
						target->chain[0] = 0x67;
						target->chain[1] = 0xe3;
						target->chain[2] = 2;
						target->chain[3] = 0xeb;
						target->chain[4] = 5;
						target->chain[5] = 0xe9;
						*((uint32_t*)&target->chain[6]) = (uint32_t)((size_t)buf - ((size_t)translatedPtr + 10));
					}
				}
				else if (type == __JUMPTARGET_JRCXZ)
				{
					int64_t diff = (int64_t)((size_t)buf - ((size_t)translatedPtr + 2));
					__CGX86_ASSERT((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL), "Near label out of range");
					if ((diff >= -0x80) && (diff <= 0x7f))
					{
						target->chain[0] = 0xe3;
						target->chain[1] = (uint8_t)diff;
						target->chain[2] = 0xeb;
						target->chain[3] = 6;
						target->chain[4] = 0xff;
					}
					else
					{
						target->chain[0] = 0xe3;
						target->chain[1] = 2;
						target->chain[2] = 0xeb;
						target->chain[3] = 6;
						target->chain[4] = 0xe9;
						*((uint32_t*)&target->chain[5]) = (uint32_t)((size_t)buf - ((size_t)translatedPtr + 9));
					}
				}
				else
				{
					int64_t diff = (int64_t)((size_t)buf - ((size_t)translatedPtr + 6));
					__CGX86_ASSERT((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL), "Near label out of range");
					target->chain[0] = 0x0f;
					target->chain[1] = (uint8_t)(0x80 + type);
					*((int32_t*)&target->chain[2]) = (int32_t)diff;
				}
			}
			else
			{
				__JumpTargetType type = (__JumpTargetType)target->chain[8];
				next = (uint8_t*)(size_t)*(uint64_t*)target->chain;
				if (type == __JUMPTARGET_ALWAYS)
				{
					int64_t diff = (int64_t)((size_t)buf - ((size_t)translatedPtr + 5));
					if ((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL))
					{
						target->chain[0] = 0xe9;
						*((int32_t*)&target->chain[1]) = (int32_t)diff;
						*((uint32_t*)&target->chain[5]) = 0xcccccccc;
					}
					else
					{
						target->chain[0] = 0xff;
						target->chain[1] = 0x25;
						*((int32_t*)&target->chain[2]) = 0;
						*((uint64_t*)&target->chain[6]) = (uint64_t)(size_t)buf;
					}
				}
				else if (type == __JUMPTARGET_JECXZ)
				{
					int64_t diff = (int64_t)((size_t)buf - ((size_t)translatedPtr + 3));
					if ((diff >= -0x80) && (diff <= 0x7f))
					{
						target->chain[0] = 0x67;
						target->chain[1] = 0xe3;
						target->chain[2] = (uint8_t)diff;
						target->chain[3] = 0xeb;
						target->chain[4] = 14;
						*((uint32_t*)&target->chain[5]) = 0xcccccccc;
					}
					else if ((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL))
					{
						target->chain[0] = 0x67;
						target->chain[1] = 0xe3;
						target->chain[2] = 2;
						target->chain[3] = 0xeb;
						target->chain[4] = 14;
						target->chain[5] = 0xe9;
						*((uint32_t*)&target->chain[6]) = (uint32_t)((size_t)buf - ((size_t)translatedPtr + 10));
					}
					else
					{
						target->chain[0] = 0x67;
						target->chain[1] = 0xe3;
						target->chain[2] = 2;
						target->chain[3] = 0xeb;
						target->chain[4] = 14;
						target->chain[5] = 0xff;
						target->chain[6] = 0x25;
						*((int32_t*)&target->chain[7]) = 0;
						*((uint64_t*)&target->chain[11]) = (uint64_t)(size_t)buf;
					}
				}
				else if (type == __JUMPTARGET_JRCXZ)
				{
					int64_t diff = (int64_t)((size_t)buf - ((size_t)translatedPtr + 2));
					if ((diff >= -0x80) && (diff <= 0x7f))
					{
						target->chain[0] = 0xe3;
						target->chain[1] = (uint8_t)diff;
						target->chain[2] = 0xeb;
						target->chain[3] = 15;
						*((uint64_t*)&target->chain[4]) = 0xccccccccccccccccLL;
					}
					else if ((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL))
					{
						target->chain[0] = 0xe3;
						target->chain[1] = 2;
						target->chain[2] = 0xeb;
						target->chain[3] = 15;
						target->chain[4] = 0xe9;
						*((uint32_t*)&target->chain[5]) = (uint32_t)((size_t)buf - ((size_t)translatedPtr + 9));
					}
					else
					{
						target->chain[0] = 0xe3;
						target->chain[1] = 2;
						target->chain[2] = 0xeb;
						target->chain[3] = 15;
						target->chain[4] = 0xff;
						target->chain[5] = 0x25;
						*((int32_t*)&target->chain[6]) = 0;
						*((uint64_t*)&target->chain[10]) = (uint64_t)(size_t)buf;
					}
				}
				else
				{
					int64_t diff = (int64_t)((size_t)buf - ((size_t)translatedPtr + 6));
					if ((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL))
					{
						target->chain[0] = 0x0f;
						target->chain[1] = (uint8_t)(0x80 + type);
						*((int32_t*)&target->chain[2]) = (int32_t)diff;
						target->chain[6] = 0xeb;
						target->chain[7] = 8;
						*((uint16_t*)&target->chain[8]) = 0xcccc;
					}
					else
					{
						target->chain[0] = (uint8_t)((0x70 + type) ^ 1);
						target->chain[1] = 14;
						target->chain[2] = 0xff;
						target->chain[3] = 0x25;
						*((int32_t*)&target->chain[4]) = 0;
						*((uint64_t*)&target->chain[8]) = (uint64_t)(size_t)buf;
					}
				}
			}
			target->chain = next;
		}
		target->addr = buf;
	}

	static __inline void __alwaysinline __PREFIX(add_label_ref) (JumpLabel* target, uint8_t* ref, __JumpTargetType type  __CGX86_ASSERT_PARAM_DECL)
	{
		if (target->nearJump)
		{
			if (target->chain == NULL)
			{
				*(uint32_t*)ref = 0;
				ref[4] = (uint8_t)type;
				if ((type == __JUMPTARGET_JCXZ) || (type == __JUMPTARGET_JECXZ))
				{
					*((uint32_t*)&ref[5]) = 0xcccccccc;
					ref[9] = 0xcc;
				}
				target->chain = ref;
			}
			else
			{
				int64_t diff = (int64_t)((size_t)target->chain - (size_t)ref);
				__CGX86_ASSERT((diff >= -0x80000000LL) && (diff <= 0x7fffffff), "Near label out of range");
				*(int32_t*)ref = (int32_t)diff;
				ref[4] = (uint8_t)type;
				if ((type == __JUMPTARGET_JCXZ) || (type == __JUMPTARGET_JECXZ))
				{
					*((uint32_t*)&ref[5]) = 0xcccccccc;
					ref[9] = 0xcc;
				}
				target->chain = ref;
			}
		}
		else
		{
			*(uint64_t*)ref = (uint64_t)(size_t)target->chain;
			ref[8] = (uint8_t)type;
			if ((type == __JUMPTARGET_JECXZ) || (type == __JUMPTARGET_JRCXZ))
			{
				*((uint64_t*)&ref[9]) = 0xccccccccccccccccLL;
				*((uint16_t*)&ref[17]) = 0xcccc;
			}
			else if (type == __JUMPTARGET_ALWAYS)
			{
				*((uint32_t*)&ref[9]) = 0xcccccccc;
				ref[13] = 0xcc;
			}
			else
			{
				*((uint32_t*)&ref[9]) = 0xcccccccc;
				*((uint16_t*)&ref[13]) = 0xcccc;
				ref[15] = 0xcc;
			}
			target->chain = ref;
		}
	}

#endif


	// Mod/RM handling routines
#ifdef __MODRM
#undef __MODRM
#endif
#ifdef __CODEGENX86_32BIT
#define __MODRM(t) __modrm32 ## _ ## t
#else
#define __MODRM(t) __modrm64 ## _ ## t
#endif

#ifdef __CODEGENX86_32BIT

	static __inline int __alwaysinline __MODRM(reg_need_rex) (uint8_t reg, uint8_t rm)
	{
		(void)reg;
		(void)rm;
		return 0;
	}

	static __inline uint8_t __alwaysinline __MODRM(reg_get_rex) (uint8_t reg, uint8_t rm)
	{
		(void)reg;
		(void)rm;
		return 0;
	}

	static __inline int __alwaysinline __MODRM(mem_need_rex) (uint8_t reg, __MEM_PARAM(m))
	{
		(void)reg;
		(void)__MEM_BASE(m);
		(void)__MEM_INDEX(m);
		(void)__MEM_SCALE(m);
		(void)__MEM_OFFSET(m);
		return 0;
	}

	static __inline uint8_t __alwaysinline __MODRM(mem_get_rex) (uint8_t reg, __MEM_PARAM(m))
	{
		(void)reg;
		(void)__MEM_BASE(m);
		(void)__MEM_INDEX(m);
		(void)__MEM_SCALE(m);
		(void)__MEM_OFFSET(m);
		return 0;
	}

	static __inline size_t __alwaysinline __MODRM(emit_noindex) (__CONTEXT_PARAMS, uint8_t reg, __MEM_PARAM(m))
	{
		__TRANSLATE_UNUSED
		(void)__MEM_INDEX(m);
		(void)__MEM_SCALE(m);
		(void)wr;
		if (__MEM_BASE(m) == NONE)
		{
			__WRITE_BUF_8_ALWAYS(0, 0x05 | (reg << 3));
			__WRITE_BUF_32_ALWAYS(1, (int32_t)__MEM_OFFSET(m));
			return 5;
		}
		else if ((__MEM_OFFSET(m) == 0) && (__MEM_BASE(m) != REG_EBP))
		{
			__WRITE_BUF_8_ALWAYS(0, __reg32(__MEM_BASE(m)) | (reg << 3));
			return 1;
		}
		else if ((__MEM_OFFSET(m) >= -0x80) && (__MEM_OFFSET(m) <= 0x7f))
		{
			__WRITE_BUF_8_8_ALWAYS(0, 0x40 | __reg32(__MEM_BASE(m)) | (reg << 3), (int8_t)__MEM_OFFSET(m));
			return 2;
		}
		else
		{
			__WRITE_BUF_8_ALWAYS(0, 0x80 | __reg32(__MEM_BASE(m)) | (reg << 3));
			__WRITE_BUF_32_ALWAYS(1, (int32_t)__MEM_OFFSET(m));
			return 5;
		}
	}

	static __inline size_t __alwaysinline __MODRM(emit_index) (__CONTEXT_PARAMS, uint8_t reg, __MEM_PARAM(m))
	{
		uint8_t scaleBits;

		__TRANSLATE_UNUSED
		(void)wr;

		__CGX86_ASSERT((__MEM_SCALE(m) == 1) || (__MEM_SCALE(m) == 2) || (__MEM_SCALE(m) == 4) || (__MEM_SCALE(m) == 8), "Invalid scale in address computation");
		if (__MEM_SCALE(m) == 1)
			scaleBits = 0x00;
		else if (__MEM_SCALE(m) == 2)
			scaleBits = 0x40;
		else if (__MEM_SCALE(m) == 4)
			scaleBits = 0x80;
		else
			scaleBits = 0xc0;

		__CGX86_ASSERT(__MEM_INDEX(m) != REG_ESP, "ESP cannot be used as an index in address computation");
		if (__MEM_INDEX(m) == NONE)
			__MEM_INDEX(m) = REG_ESP; // No index takes place of ESP as index

		if (__MEM_BASE(m) == NONE)
		{
			__WRITE_BUF_8_8_ALWAYS(0, 0x04 | (reg << 3), 0x05 | (__reg32(__MEM_INDEX(m)) << 3) | scaleBits);
			__WRITE_BUF_32_ALWAYS(2, (int32_t)__MEM_OFFSET(m));
			return 6;
		}
		else if ((__MEM_OFFSET(m) == 0) && (__MEM_BASE(m) != REG_EBP))
		{
			__WRITE_BUF_8_8_ALWAYS(0, 0x04 | (reg << 3), __reg32(__MEM_BASE(m)) | (__reg32(__MEM_INDEX(m)) << 3) | scaleBits);
			return 2;
		}
		else if ((__MEM_OFFSET(m) >= -0x80) && (__MEM_OFFSET(m) <= 0x7f))
		{
			__WRITE_BUF_8_8_ALWAYS(0, 0x44 | (reg << 3), __reg32(__MEM_BASE(m)) | (__reg32(__MEM_INDEX(m)) << 3) | scaleBits);
			__WRITE_BUF_8_ALWAYS(2, (int8_t)__MEM_OFFSET(m));
			return 3;
		}
		else
		{
			__WRITE_BUF_8_8_ALWAYS(0, 0x84 | (reg << 3), __reg32(__MEM_BASE(m)) | (__reg32(__MEM_INDEX(m)) << 3) | scaleBits);
			__WRITE_BUF_32_ALWAYS(2, (int32_t)__MEM_OFFSET(m));
			return 6;
		}
	}

	static __inline size_t __alwaysinline __MODRM(emit_noindex_lenonly) (__MEM_PARAM(m))
	{
		(void)__MEM_INDEX(m);
		(void)__MEM_SCALE(m);
		if (__MEM_BASE(m) == NONE)
			return 5;
		else if ((__MEM_OFFSET(m) == 0) && (__MEM_BASE(m) != REG_EBP))
			return 1;
		else if ((__MEM_OFFSET(m) >= -0x80) && (__MEM_OFFSET(m) <= 0x7f))
			return 2;
		else
			return 5;
	}

	static __inline size_t __alwaysinline __MODRM(emit_index_lenonly) (__MEM_PARAM(m))
	{
		(void)__MEM_INDEX(m);
		(void)__MEM_SCALE(m);
		if (__MEM_BASE(m) == NONE)
			return 6;
		else if ((__MEM_OFFSET(m) == 0) && (__MEM_BASE(m) != REG_EBP))
			return 2;
		else if ((__MEM_OFFSET(m) >= -0x80) && (__MEM_OFFSET(m) <= 0x7f))
			return 3;
		else
			return 6;
	}

	static __inline size_t __alwaysinline __MODRM(emit) (__CONTEXT_PARAMS, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		__TRANSLATE_UNUSED
		(void)immsz;
		if (wr)
		{
			if ((__MEM_INDEX(m) == NONE) && (__MEM_BASE(m) != REG_ESP))
				return __MODRM(emit_noindex) (__CONTEXT, reg, __MEMOP(m));
			else // Index present or base of ESP
				return __MODRM(emit_index) (__CONTEXT, reg, __MEMOP(m));
		}
		else
		{
			if ((__MEM_INDEX(m) == NONE) && (__MEM_BASE(m) != REG_ESP))
				return __MODRM(emit_noindex_lenonly) (__MEMOP(m));
			else // Index present or base of ESP
				return __MODRM(emit_index_lenonly) (__MEMOP(m));
		}
	}

#else // __CODEGENX86_64BIT

	static __inline int __alwaysinline __MODRM(reg_need_rex) (uint8_t reg, uint8_t rm)
	{
		// Must use >= 8 here instead of & 8, see __reg8_64bit function
		return (reg >= 8) || (rm >= 8);
	}

	static __inline uint8_t __alwaysinline __MODRM(reg_get_rex) (uint8_t reg, uint8_t rm)
	{
		return __REX(__REX_REG(reg) | __REX_RM(rm));
	}

	static __inline int __alwaysinline __MODRM(mem_need_rex) (uint8_t reg, __MEM_PARAM(m))
	{
		(void)__MEM_SCALE(m);
		(void)__MEM_OFFSET(m);
		// Must use >= 8 here instead of & 8, see __reg8_64bit function
		return (reg >= 8) || (__MEM_BASE(m) >= REG_R8) || (__MEM_INDEX(m) >= REG_R8);
	}

	static __inline uint8_t __alwaysinline __MODRM(mem_get_rex) (uint8_t reg, __MEM_PARAM(m))
	{
		uint8_t rex = __REX(__REX_REG(reg));
		(void)__MEM_SCALE(m);
		(void)__MEM_OFFSET(m);
		if (__MEM_BASE(m) != NONE)
			rex |= __REX_RM(__MEM_BASE(m) - REG_RAX);
		if (__MEM_INDEX(m) != NONE)
			rex |= __REX_INDEX(__MEM_INDEX(m) - REG_RAX);
		return rex;
	}

	static __inline size_t __alwaysinline __MODRM(emit_noindex) (__CONTEXT_PARAMS, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		(void)wr;
		(void)__MEM_INDEX(m);
		(void)__MEM_SCALE(m);
		if (__MEM_BASE(m) == NONE)
		{
			int64_t diff = (int64_t)(size_t)__MEM_OFFSET(m) - (int64_t)((size_t)__EXEC_OFFSET(5 + immsz));
			if ((diff >= -0x80000000LL) && (diff < 0x7fffffffLL))
			{
				__WRITE_BUF_8_ALWAYS(0, 0x05 | ((reg & 7) << 3));
				__WRITE_BUF_32_ALWAYS(1, (int32_t)diff);
				return 5;
			}
			else
			{
				__CGX86_ASSERT(((uint64_t)__MEM_OFFSET(m)) < 0x100000000LL, "Memory address out of range");
				__WRITE_BUF_8_8_ALWAYS(0, 0x04 | ((reg & 7) << 3), 0x25);
				__WRITE_BUF_32_ALWAYS(2, (int32_t)__MEM_OFFSET(m));
				return 6;
			}
		}
		else if (__MEM_BASE(m) == REG_RIP)
		{
			__WRITE_BUF_8_ALWAYS(0, 0x05 | ((reg & 7) << 3));
			__WRITE_BUF_32_ALWAYS(1, (int32_t)__MEM_OFFSET(m));
			return 5;
		}
		else if ((__MEM_OFFSET(m) == 0) && (__MEM_BASE(m) != REG_RBP) && (__MEM_BASE(m) != REG_R13))
		{
			__WRITE_BUF_8_ALWAYS(0, (__reg64(__MEM_BASE(m)) & 7) | ((reg & 7) << 3));
			return 1;
		}
		else if ((__MEM_OFFSET(m) >= -0x80) && (__MEM_OFFSET(m) <= 0x7f))
		{
			__WRITE_BUF_8_8_ALWAYS(0, 0x40 | (__reg64(__MEM_BASE(m)) & 7) | ((reg & 7) << 3), (int8_t)__MEM_OFFSET(m));
			return 2;
		}
		else
		{
			__WRITE_BUF_8_ALWAYS(0, 0x80 | (__reg64(__MEM_BASE(m)) & 7) | ((reg & 7) << 3));
			__WRITE_BUF_32_ALWAYS(1, (int32_t)__MEM_OFFSET(m));
			return 5;
		}
	}

	static __inline size_t __alwaysinline __MODRM(emit_index) (__CONTEXT_PARAMS, uint8_t reg, __MEM_PARAM(m))
	{
		uint8_t scaleBits;

		__TRANSLATE_UNUSED
		(void)wr;

		__CGX86_ASSERT((__MEM_SCALE(m) == 1) || (__MEM_SCALE(m) == 2) || (__MEM_SCALE(m) == 4) || (__MEM_SCALE(m) == 8), "Invalid scale in address computation");
		if (__MEM_SCALE(m) == 1)
			scaleBits = 0x00;
		else if (__MEM_SCALE(m) == 2)
			scaleBits = 0x40;
		else if (__MEM_SCALE(m) == 4)
			scaleBits = 0x80;
		else
			scaleBits = 0xc0;

		__CGX86_ASSERT(__MEM_INDEX(m) != REG_RSP, "RSP cannot be used as an index in address computation");
		if (__MEM_INDEX(m) == NONE)
			__MEM_INDEX(m) = REG_RSP; // No index takes place of ESP as index

#ifdef __x86_64__
		__CGX86_ASSERT(((__MEM_OFFSET(m)) >= -0x80000000LL) && ((__MEM_OFFSET(m)) <= 0x7fffffffLL), "Offset out of range");
#endif
		if (__MEM_BASE(m) == NONE)
		{
			__WRITE_BUF_8_8_ALWAYS(0, 0x04 | ((reg & 7) << 3), 0x05 | ((__reg64(__MEM_INDEX(m)) & 7) << 3) | scaleBits);
			__WRITE_BUF_32_ALWAYS(2, (int32_t)__MEM_OFFSET(m));
			return 6;
		}
		else if ((__MEM_OFFSET(m) == 0) && (__MEM_BASE(m) != REG_RBP) && (__MEM_BASE(m) != REG_R13))
		{
			__WRITE_BUF_8_8_ALWAYS(0, 0x04 | ((reg & 7) << 3), (__reg64(__MEM_BASE(m)) & 7) | ((__reg64(__MEM_INDEX(m)) & 7) << 3) | scaleBits);
			return 2;
		}
		else if ((__MEM_OFFSET(m) >= -0x80) && (__MEM_OFFSET(m) <= 0x7f))
		{
			__WRITE_BUF_8_8_ALWAYS(0, 0x44 | ((reg & 7) << 3), (__reg64(__MEM_BASE(m)) & 7) | ((__reg64(__MEM_INDEX(m)) & 7) << 3) | scaleBits);
			__WRITE_BUF_8_ALWAYS(2, (int8_t)__MEM_OFFSET(m));
			return 3;
		}
		else
		{
			__WRITE_BUF_8_8_ALWAYS(0, 0x84 | ((reg & 7) << 3), (__reg64(__MEM_BASE(m)) & 7) | ((__reg64(__MEM_INDEX(m)) & 7) << 3) | scaleBits);
			__WRITE_BUF_32_ALWAYS(2, (int32_t)__MEM_OFFSET(m));
			return 6;
		}
	}

	static __inline size_t __alwaysinline __MODRM(emit_noindex_lenonly) (__MEM_PARAM(m))
	{
		(void)__MEM_INDEX(m);
		(void)__MEM_SCALE(m);
		if (__MEM_BASE(m) == NONE)
			return 6;
		else if (__MEM_BASE(m) == REG_RIP)
			return 5;
		else if ((__MEM_OFFSET(m) == 0) && (__MEM_BASE(m) != REG_RBP) && (__MEM_BASE(m) != REG_R13))
			return 1;
		else if ((__MEM_OFFSET(m) >= -0x80) && (__MEM_OFFSET(m) <= 0x7f))
			return 2;
		else
			return 5;
	}

	static __inline size_t __alwaysinline __MODRM(emit_index_lenonly) (__MEM_PARAM(m))
	{
		(void)__MEM_INDEX(m);
		(void)__MEM_SCALE(m);
		if (__MEM_BASE(m) == NONE)
			return 6;
		else if ((__MEM_OFFSET(m) == 0) && (__MEM_BASE(m) != REG_RBP) && (__MEM_BASE(m) != REG_R13))
			return 2;
		else if ((__MEM_OFFSET(m) >= -0x80) && (__MEM_OFFSET(m) <= 0x7f))
			return 3;
		else
			return 6;
	}

	static __inline size_t __alwaysinline __MODRM(emit) (__CONTEXT_PARAMS, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		if (wr)
		{
			if ((__MEM_INDEX(m) == NONE) && (__MEM_BASE(m) != REG_RSP) && (__MEM_BASE(m) != REG_R12))
				return __MODRM(emit_noindex) (__CONTEXT, reg, __MEMOP(m), immsz);
			else // Index present or base of RSP/R12
				return __MODRM(emit_index) (__CONTEXT, reg, __MEMOP(m));
		}
		else
		{
			if ((__MEM_INDEX(m) == NONE) && (__MEM_BASE(m) != REG_RSP) && (__MEM_BASE(m) != REG_R12))
				return __MODRM(emit_noindex_lenonly) (__MEMOP(m));
			else // Index present or base of RSP/R12
				return __MODRM(emit_index_lenonly) (__MEMOP(m));
		}
	}

#endif

#define __ASSERT_NO_INVALID_8BIT_COMBO __CGX86_ASSERT(!(((a >= 20) && (a <= 23) && (b >= 24)) || ((b >= 20) && (b <= 23) && (a >= 24))), "AH/CH/DH/BH registers cannot be used at the same time as SPL/BPL/SIL/DIL/R8B-R15B");

	static __inline size_t __alwaysinline __MODRM(reg_onebyte) (__CONTEXT_PARAMS, uint8_t op, uint8_t a, uint8_t b)
	{
		__TRANSLATE_UNUSED
		__ASSERT_NO_INVALID_8BIT_COMBO
		if (__MODRM(reg_need_rex) (a, b))
		{
			__WRITE_BUF_8_8(0, __MODRM(reg_get_rex) (a, b), op);
			__WRITE_BUF_8(2, 0xc0 | ((a & 7) << 3) | (b & 7));
			return 3;
		}
		else
		{
			__WRITE_BUF_8_8(0, op, 0xc0 | (a << 3) | b);
			return 2;
		}
	}

	static __inline size_t __alwaysinline __MODRM(mem_onebyte) (__CONTEXT_PARAMS, uint8_t op, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		if (__MODRM(mem_need_rex) (reg, __MEMOP(m)))
		{
			__WRITE_BUF_8_8(0, __MODRM(mem_get_rex) (reg, __MEMOP(m)), op);
			return __MODRM(emit) (__CONTEXT_OFFSET(2), reg, __MEMOP(m), immsz) + 2;
		}
		else
		{
			__WRITE_BUF_8(0, op);
			return __MODRM(emit) (__CONTEXT_OFFSET(1), reg, __MEMOP(m), immsz) + 1;
		}
	}

	static __inline size_t __alwaysinline __MODRM(reg_onebyte_opsz) (__CONTEXT_PARAMS, uint8_t op, uint8_t a, uint8_t b)
	{
		__TRANSLATE_UNUSED
		__ASSERT_NO_INVALID_8BIT_COMBO
		if (__MODRM(reg_need_rex) (a, b))
		{
			__WRITE_BUF_8_8_8_8(0, 0x66, __MODRM(reg_get_rex) (a, b), op, 0xc0 | ((a & 7) << 3) | (b & 7));
			return 4;
		}
		else
		{
			__WRITE_BUF_8_8(0, 0x66, op);
			__WRITE_BUF_8(2, 0xc0 | (a << 3) | b);
			return 3;
		}
	}

	static __inline size_t __alwaysinline __MODRM(mem_onebyte_opsz) (__CONTEXT_PARAMS, uint8_t op, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		if (__MODRM(mem_need_rex) (reg, __MEMOP(m)))
		{
			__WRITE_BUF_8_8(0, 0x66, __MODRM(mem_get_rex) (reg, __MEMOP(m)));
			__WRITE_BUF_8(2, op);
			return __MODRM(emit) (__CONTEXT_OFFSET(3), reg, __MEMOP(m), immsz) + 3;
		}
		else
		{
			__WRITE_BUF_8_8(0, 0x66, op);
			return __MODRM(emit) (__CONTEXT_OFFSET(2), reg, __MEMOP(m), immsz) + 2;
		}
	}

	static __inline size_t __alwaysinline __MODRM(reg_onebyte_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, uint8_t a, int8_t imm)
	{
		size_t ofs = __MODRM(reg_onebyte) (__CONTEXT, op, grp, a);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(mem_onebyte_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, __MEM_PARAM(m), int8_t imm)
	{
		size_t ofs = __MODRM(mem_onebyte) (__CONTEXT, op, grp, __MEMOP(m), 1);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(reg_onebyte_imm16) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, uint8_t a, int16_t imm)
	{
		size_t ofs = __MODRM(reg_onebyte) (__CONTEXT, op, grp, a);
		__WRITE_BUF_16(ofs, imm);
		return ofs + 2;
	}

	static __inline size_t __alwaysinline __MODRM(mem_onebyte_imm16) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, __MEM_PARAM(m), int16_t imm)
	{
		size_t ofs = __MODRM(mem_onebyte) (__CONTEXT, op, grp, __MEMOP(m), 2);
		__WRITE_BUF_16(ofs, imm);
		return ofs + 2;
	}

	static __inline size_t __alwaysinline __MODRM(reg_onebyte_imm32) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, uint8_t a, int32_t imm)
	{
		size_t ofs = __MODRM(reg_onebyte) (__CONTEXT, op, grp, a);
		__WRITE_BUF_32(ofs, imm);
		return ofs + 4;
	}

	static __inline size_t __alwaysinline __MODRM(mem_onebyte_imm32) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, __MEM_PARAM(m), int32_t imm)
	{
		size_t ofs = __MODRM(mem_onebyte) (__CONTEXT, op, grp, __MEMOP(m), 4);
		__WRITE_BUF_32(ofs, imm);
		return ofs + 4;
	}

	static __inline size_t __alwaysinline __MODRM(reg_onebyte_opsz_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, uint8_t a, int8_t imm)
	{
		size_t ofs = __MODRM(reg_onebyte_opsz) (__CONTEXT, op, grp, a);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(mem_onebyte_opsz_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, __MEM_PARAM(m), int8_t imm)
	{
		size_t ofs = __MODRM(mem_onebyte_opsz) (__CONTEXT, op, grp, __MEMOP(m), 1);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(reg_onebyte_opsz_imm16) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, uint8_t a, int16_t imm)
	{
		size_t ofs = __MODRM(reg_onebyte_opsz) (__CONTEXT, op, grp, a);
		__WRITE_BUF_16(ofs, imm);
		return ofs + 2;
	}

	static __inline size_t __alwaysinline __MODRM(mem_onebyte_opsz_imm16) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, __MEM_PARAM(m), int16_t imm)
	{
		size_t ofs = __MODRM(mem_onebyte_opsz) (__CONTEXT, op, grp, __MEMOP(m), 2);
		__WRITE_BUF_16(ofs, imm);
		return ofs + 2;
	}

	static __inline size_t __alwaysinline __MODRM(reg_twobyte) (__CONTEXT_PARAMS, uint8_t op, uint8_t a, uint8_t b)
	{
		__TRANSLATE_UNUSED
		__ASSERT_NO_INVALID_8BIT_COMBO
		if (__MODRM(reg_need_rex) (a, b))
		{
			__WRITE_BUF_8_8_8_8(0, __MODRM(reg_get_rex) (a, b), 0x0f, op, 0xc0 | ((a & 7) << 3) | (b & 7));
			return 4;
		}
		else
		{
			__WRITE_BUF_8_8(0, 0x0f, op);
			__WRITE_BUF_8(2, 0xc0 | (a << 3) | b);
			return 3;
		}
	}

	static __inline size_t __alwaysinline __MODRM(reg_twobyte_prefix) (__CONTEXT_PARAMS, uint8_t prefix, uint8_t op, uint8_t a, uint8_t b)
	{
		__TRANSLATE_UNUSED
		__ASSERT_NO_INVALID_8BIT_COMBO
		if (__MODRM(reg_need_rex) (a, b))
		{
			__WRITE_BUF_8(0, prefix);
			__WRITE_BUF_8_8_8_8(1, __MODRM(reg_get_rex) (a, b), 0x0f, op, 0xc0 | ((a & 7) << 3) | (b & 7));
			return 5;
		}
		else
		{
			__WRITE_BUF_8_8(0, prefix, 0x0f);
			__WRITE_BUF_8_8(2, op, 0xc0 | (a << 3) | b);
			return 4;
		}
	}

	static __inline size_t __alwaysinline __MODRM(reg_threebyte) (__CONTEXT_PARAMS, uint8_t op, uint8_t op2, uint8_t a, uint8_t b)
	{
		__TRANSLATE_UNUSED
		__ASSERT_NO_INVALID_8BIT_COMBO
		if (__MODRM(reg_need_rex) (a, b))
		{
			__WRITE_BUF_8_8_8_8(0, __MODRM(reg_get_rex) (a, b), 0x0f, op, op2);
			__WRITE_BUF_8(4, 0xc0 | ((a & 7) << 3) | (b & 7));
			return 5;
		}
		else
		{
			__WRITE_BUF_8_8_8_8(0, 0x0f, op, op2, 0xc0 | (a << 3) | b);
			return 4;
		}
	}

	static __inline size_t __alwaysinline __MODRM(reg_threebyte_prefix) (__CONTEXT_PARAMS, uint8_t prefix, uint8_t op, uint8_t op2, uint8_t a, uint8_t b)
	{
		__TRANSLATE_UNUSED
		__ASSERT_NO_INVALID_8BIT_COMBO
		if (__MODRM(reg_need_rex) (a, b))
		{
			__WRITE_BUF_8_8(0, prefix, __MODRM(reg_get_rex) (a, b));
			__WRITE_BUF_8_8_8_8(2, 0x0f, op, op2, 0xc0 | ((a & 7) << 3) | (b & 7));
			return 6;
		}
		else
		{
			__WRITE_BUF_8(0, prefix);
			__WRITE_BUF_8_8_8_8(1, 0x0f, op, op2, 0xc0 | (a << 3) | b);
			return 5;
		}
	}

	static __inline size_t __alwaysinline __MODRM(mem_twobyte) (__CONTEXT_PARAMS, uint8_t op, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		if (__MODRM(mem_need_rex) (reg, __MEMOP(m)))
		{
			__WRITE_BUF_8_8(0, __MODRM(mem_get_rex) (reg, __MEMOP(m)), 0x0f);
			__WRITE_BUF_8(2, op);
			return __MODRM(emit) (__CONTEXT_OFFSET(3), reg, __MEMOP(m), immsz) + 3;
		}
		else
		{
			__WRITE_BUF_8_8(0, 0x0f, op);
			return __MODRM(emit) (__CONTEXT_OFFSET(2), reg, __MEMOP(m), immsz) + 2;
		}
	}

	static __inline size_t __alwaysinline __MODRM(mem_twobyte_prefix) (__CONTEXT_PARAMS, uint8_t prefix, uint8_t op, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		if (__MODRM(mem_need_rex) (reg, __MEMOP(m)))
		{
			__WRITE_BUF_8_8(0, prefix, __MODRM(mem_get_rex) (reg, __MEMOP(m)));
			__WRITE_BUF_8_8(2, 0x0f, op);
			return __MODRM(emit) (__CONTEXT_OFFSET(4), reg, __MEMOP(m), immsz) + 4;
		}
		else
		{
			__WRITE_BUF_8(0, prefix);
			__WRITE_BUF_8_8(1, 0x0f, op);
			return __MODRM(emit) (__CONTEXT_OFFSET(3), reg, __MEMOP(m), immsz) + 3;
		}
	}

	static __inline size_t __alwaysinline __MODRM(mem_threebyte) (__CONTEXT_PARAMS, uint8_t op, uint8_t op2, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		if (__MODRM(mem_need_rex) (reg, __MEMOP(m)))
		{
			__WRITE_BUF_8_8(0, __MODRM(mem_get_rex) (reg, __MEMOP(m)), 0x0f);
			__WRITE_BUF_8_8(2, op, op2);
			return __MODRM(emit) (__CONTEXT_OFFSET(4), reg, __MEMOP(m), immsz) + 4;
		}
		else
		{
			__WRITE_BUF_8(0, 0x0f);
			__WRITE_BUF_8_8(1, op, op2);
			return __MODRM(emit) (__CONTEXT_OFFSET(3), reg, __MEMOP(m), immsz) + 3;
		}
	}

	static __inline size_t __alwaysinline __MODRM(mem_threebyte_prefix) (__CONTEXT_PARAMS, uint8_t prefix, uint8_t op, uint8_t op2, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		if (__MODRM(mem_need_rex) (reg, __MEMOP(m)))
		{
			__WRITE_BUF_8_8(0, prefix, __MODRM(mem_get_rex) (reg, __MEMOP(m)));
			__WRITE_BUF_8_8(2, 0x0f, op);
			__WRITE_BUF_8(4, op2);
			return __MODRM(emit) (__CONTEXT_OFFSET(5), reg, __MEMOP(m), immsz) + 5;
		}
		else
		{
			__WRITE_BUF_8_8(0, prefix, 0x0f);
			__WRITE_BUF_8_8(2, op, op2);
			return __MODRM(emit) (__CONTEXT_OFFSET(4), reg, __MEMOP(m), immsz) + 4;
		}
	}

	static __inline size_t __alwaysinline __MODRM(reg_twobyte_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, uint8_t a, int8_t imm)
	{
		size_t ofs = __MODRM(reg_twobyte) (__CONTEXT, op, grp, a);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(reg_twobyte_imm8_prefix) (__CONTEXT_PARAMS, uint8_t prefix, uint8_t op, uint8_t grp, uint8_t a, int8_t imm)
	{
		size_t ofs = __MODRM(reg_twobyte_prefix) (__CONTEXT, prefix, op, grp, a);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(reg_threebyte_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t op2, uint8_t grp, uint8_t a, int8_t imm)
	{
		size_t ofs = __MODRM(reg_threebyte) (__CONTEXT, op, op2, grp, a);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(reg_threebyte_imm8_prefix) (__CONTEXT_PARAMS, uint8_t prefix, uint8_t op, uint8_t op2, uint8_t grp, uint8_t a, int8_t imm)
	{
		size_t ofs = __MODRM(reg_threebyte_prefix) (__CONTEXT, prefix, op, op2, grp, a);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(mem_twobyte_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, __MEM_PARAM(m), int8_t imm)
	{
		size_t ofs = __MODRM(mem_twobyte) (__CONTEXT, op, grp, __MEMOP(m), 1);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(mem_twobyte_imm8_prefix) (__CONTEXT_PARAMS, uint8_t prefix, uint8_t op, uint8_t grp, __MEM_PARAM(m), int8_t imm)
	{
		size_t ofs = __MODRM(mem_twobyte_prefix) (__CONTEXT, prefix, op, grp, __MEMOP(m), 1);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(mem_threebyte_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t op2, uint8_t grp, __MEM_PARAM(m), int8_t imm)
	{
		size_t ofs = __MODRM(mem_threebyte) (__CONTEXT, op, op2, grp, __MEMOP(m), 1);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(mem_threebyte_imm8_prefix) (__CONTEXT_PARAMS, uint8_t prefix, uint8_t op, uint8_t op2, uint8_t grp, __MEM_PARAM(m), int8_t imm)
	{
		size_t ofs = __MODRM(mem_threebyte_prefix) (__CONTEXT, prefix, op, op2, grp, __MEMOP(m), 1);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(reg_twobyte_opsz) (__CONTEXT_PARAMS, uint8_t op, uint8_t a, uint8_t b)
	{
		__TRANSLATE_UNUSED
		__ASSERT_NO_INVALID_8BIT_COMBO
		if (__MODRM(reg_need_rex) (a, b))
		{
			__WRITE_BUF_8_8_8_8(0, 0x66, __MODRM(reg_get_rex) (a, b), 0x0f, op);
			__WRITE_BUF_8(4, 0xc0 | ((a & 7) << 3) | (b & 7));
			return 5;
		}
		else
		{
			__WRITE_BUF_8_8_8_8(0, 0x66, 0x0f, op, 0xc0 | (a << 3) | b);
			return 4;
		}
	}

	static __inline size_t __alwaysinline __MODRM(mem_twobyte_opsz) (__CONTEXT_PARAMS, uint8_t op, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		if (__MODRM(mem_need_rex) (reg, __MEMOP(m)))
		{
			__WRITE_BUF_8_8_8_8(0, 0x66, __MODRM(mem_get_rex) (reg, __MEMOP(m)), 0x0f, op);
			return __MODRM(emit) (__CONTEXT_OFFSET(4), reg, __MEMOP(m), immsz) + 4;
		}
		else
		{
			__WRITE_BUF_8_8(0, 0x66, 0x0f);
			__WRITE_BUF_8(2, op);
			return __MODRM(emit) (__CONTEXT_OFFSET(3), reg, __MEMOP(m), immsz) + 3;
		}
	}

	static __inline size_t __alwaysinline __MODRM(reg_twobyte_opsz_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, uint8_t a, int8_t imm)
	{
		size_t ofs = __MODRM(reg_twobyte_opsz) (__CONTEXT, op, grp, a);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(mem_twobyte_opsz_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, __MEM_PARAM(m), int8_t imm)
	{
		size_t ofs = __MODRM(mem_twobyte_opsz) (__CONTEXT, op, grp, __MEMOP(m), 1);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

#ifdef __CODEGENX86_64BIT
	static __inline size_t __alwaysinline __MODRM(reg_onebyte64) (__CONTEXT_PARAMS, uint8_t op, uint8_t a, uint8_t b)
	{
		__TRANSLATE_UNUSED
		__WRITE_BUF_8_8(0, __MODRM(reg_get_rex) (a, b) | __REX_64, op);
		__WRITE_BUF_8(2, 0xc0 | ((a & 7) << 3) | (b & 7));
		return 3;
	}

	static __inline size_t __alwaysinline __MODRM(mem_onebyte64) (__CONTEXT_PARAMS, uint8_t op, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		__WRITE_BUF_8_8(0, __MODRM(mem_get_rex) (reg, __MEMOP(m)) | __REX_64, op);
		return __MODRM(emit) (__CONTEXT_OFFSET(2), reg, __MEMOP(m), immsz) + 2;
	}

	static __inline size_t __alwaysinline __MODRM(reg_onebyte64_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, uint8_t a, int8_t imm)
	{
		size_t ofs = __MODRM(reg_onebyte64) (__CONTEXT, op, grp, a);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(mem_onebyte64_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, __MEM_PARAM(m), int8_t imm)
	{
		size_t ofs = __MODRM(mem_onebyte64) (__CONTEXT, op, grp, __MEMOP(m), 1);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(reg_onebyte64_imm16) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, uint8_t a, int16_t imm)
	{
		size_t ofs = __MODRM(reg_onebyte64) (__CONTEXT, op, grp, a);
		__WRITE_BUF_16(ofs, imm);
		return ofs + 2;
	}

	static __inline size_t __alwaysinline __MODRM(mem_onebyte64_imm16) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, __MEM_PARAM(m), int16_t imm)
	{
		size_t ofs = __MODRM(mem_onebyte64) (__CONTEXT, op, grp, __MEMOP(m), 2);
		__WRITE_BUF_16(ofs, imm);
		return ofs + 2;
	}

	static __inline size_t __alwaysinline __MODRM(reg_onebyte64_imm32) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, uint8_t a, int32_t imm)
	{
		size_t ofs = __MODRM(reg_onebyte64) (__CONTEXT, op, grp, a);
		__WRITE_BUF_32(ofs, imm);
		return ofs + 4;
	}

	static __inline size_t __alwaysinline __MODRM(mem_onebyte64_imm32) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, __MEM_PARAM(m), int32_t imm)
	{
		size_t ofs = __MODRM(mem_onebyte64) (__CONTEXT, op, grp, __MEMOP(m), 4);
		__WRITE_BUF_32(ofs, imm);
		return ofs + 4;
	}

	static __inline size_t __alwaysinline __MODRM(reg_twobyte64) (__CONTEXT_PARAMS, uint8_t op, uint8_t a, uint8_t b)
	{
		__TRANSLATE_UNUSED
		__WRITE_BUF_8_8_8_8(0, __MODRM(reg_get_rex) (a, b) | __REX_64, 0x0f, op, 0xc0 | ((a & 7) << 3) | (b & 7));
		return 4;
	}

	static __inline size_t __alwaysinline __MODRM(reg_twobyte64_prefix) (__CONTEXT_PARAMS, uint8_t prefix, uint8_t op, uint8_t a, uint8_t b)
	{
		__TRANSLATE_UNUSED
		__WRITE_BUF_8(0, prefix);
		__WRITE_BUF_8_8_8_8(1, __MODRM(reg_get_rex) (a, b) | __REX_64, 0x0f, op, 0xc0 | ((a & 7) << 3) | (b & 7));
		return 5;
	}

	static __inline size_t __alwaysinline __MODRM(mem_twobyte64) (__CONTEXT_PARAMS, uint8_t op, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		__WRITE_BUF_8_8(0, __MODRM(mem_get_rex) (reg, __MEMOP(m)) | __REX_64, 0x0f);
		__WRITE_BUF_8(2, op);
		return __MODRM(emit) (__CONTEXT_OFFSET(3), reg, __MEMOP(m), immsz) + 3;
	}

	static __inline size_t __alwaysinline __MODRM(mem_twobyte64_prefix) (__CONTEXT_PARAMS, uint8_t prefix, uint8_t op, uint8_t reg, __MEM_PARAM(m), uint8_t immsz)
	{
		__WRITE_BUF_8_8(0, prefix, __MODRM(mem_get_rex) (reg, __MEMOP(m)) | __REX_64);
		__WRITE_BUF_8_8(2, 0x0f, op);
		return __MODRM(emit) (__CONTEXT_OFFSET(4), reg, __MEMOP(m), immsz) + 4;
	}

	static __inline size_t __alwaysinline __MODRM(reg_twobyte64_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, uint8_t a, int8_t imm)
	{
		size_t ofs = __MODRM(reg_twobyte64) (__CONTEXT, op, grp, a);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}

	static __inline size_t __alwaysinline __MODRM(mem_twobyte64_imm8) (__CONTEXT_PARAMS, uint8_t op, uint8_t grp, __MEM_PARAM(m), int8_t imm)
	{
		size_t ofs = __MODRM(mem_twobyte64) (__CONTEXT, op, grp, __MEMOP(m), 1);
		__WRITE_BUF_8(ofs, imm);
		return ofs + 1;
	}
#endif


	// Jump/call instructions

	__DEF_INSTR_1(calln, p, __PTR)
	{
#ifdef __CODEGENX86_32BIT
		__WRITE_BUF_8(0, 0xe8);
		__WRITE_BUF_32(1, (int32_t)((size_t)a - ((size_t)__EXEC_OFFSET(5))));
		return 5;
#else
		int64_t diff;
		if (!wr)
			return 16;
		diff = (int64_t)((size_t)a - ((size_t)__EXEC_OFFSET(5)));
		if ((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL))
		{
			__WRITE_BUF_8(0, 0xe8);
			__WRITE_BUF_32(1, (int32_t)diff);
			return 5;
		}
		else
		{
			__WRITE_BUF_8_8(0, 0xff, 0x15);
			__WRITE_BUF_32(2, 2);
			__WRITE_BUF_8_8(6, 0xeb, 8);
			__WRITE_BUF_64(8, (uint64_t)(size_t)a);
			return 16;
		}
#endif
	}

	__DEF_INSTR_1(jmpn, p, __PTR)
	{
#ifdef __CODEGENX86_32BIT
		__WRITE_BUF_8(0, 0xe9);
		__WRITE_BUF_32(1, (int32_t)((size_t)a - ((size_t)__EXEC_OFFSET(5))));
		return 5;
#else
		int64_t diff;
		if (!wr)
			return 14;
		diff = (int64_t)((size_t)a - ((size_t)__EXEC_OFFSET(5)));
		if ((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL))
		{
			__WRITE_BUF_8(0, 0xe9);
			__WRITE_BUF_32(1, (int32_t)diff);
			return 5;
		}
		else
		{
			__WRITE_BUF_8_8(0, 0xff, 0x25);
			__WRITE_BUF_32(2, 0);
			__WRITE_BUF_64(6, (uint64_t)(size_t)a);
			return 14;
		}
#endif
	}

	__DEF_INSTR_1(jmpn, t, __TARGET)
	{
		if (a->addr != 0)
			return __NAME(jmpn, p) (__CONTEXT, a->addr);
		if (wr)
			__PREFIX(add_label_ref) (a, buf, __JUMPTARGET_ALWAYS  __CGX86_ASSERT_PARAMS);
		return a->nearJump ? __FORWARD_REF_NEAR_JUMP_SIZE : __FORWARD_REF_JUMP_SIZE;
	}

	__DEF_INSTR_1_ARG(condjmp, p, __PTR, uint8_t cond)
	{
#ifdef __CODEGENX86_32BIT
		int32_t diff;
		if (!wr)
			return 6;
		diff = (int32_t)((size_t)a - ((size_t)__EXEC_OFFSET(2)));
		if ((diff >= -0x80) && (diff <= 0x7f))
		{
			__WRITE_BUF_8(0, 0x70 + cond);
			__WRITE_BUF_8(1, (int8_t)diff);
			return 2;
		}
		else
		{
			__WRITE_BUF_8_8(0, 0x0f, 0x80 + cond);
			__WRITE_BUF_32(2, (int32_t)((size_t)a - ((size_t)__EXEC_OFFSET(6))));
			return 6;
		}
#else
		int64_t diff;
		if (!wr)
			return 16;
		diff = (int64_t)((size_t)a - ((size_t)__EXEC_OFFSET(2)));
		if ((diff >= -0x80) && (diff <= 0x7f))
		{
			__WRITE_BUF_8(0, 0x70 + cond);
			__WRITE_BUF_8(1, (int8_t)diff);
			return 2;
		}
		diff = (int64_t)((size_t)a - ((size_t)__EXEC_OFFSET(6)));
		if ((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL))
		{
			__WRITE_BUF_8_8(0, 0x0f, 0x80 + cond);
			__WRITE_BUF_32(2, (int32_t)diff);
			return 6;
		}
		else
		{
			__WRITE_BUF_8_8_8_8(0, (0x70 + cond) ^ 1, 14, 0xff, 0x25);
			__WRITE_BUF_32(4, 0);
			__WRITE_BUF_64(8, (uint64_t)(size_t)a);
			return 16;
		}
#endif
	}

	__DEF_INSTR_1_ARG(condjmp, t, __TARGET, uint8_t cond)
	{
		if (a->addr != 0)
			return __NAME(condjmp, p) (__CONTEXT, cond, a->addr);
		if (wr)
			__PREFIX(add_label_ref) (a, buf, (__JumpTargetType)cond  __CGX86_ASSERT_PARAMS);
		return a->nearJump ? __FORWARD_REF_COND_NEAR_JUMP_SIZE : __FORWARD_REF_COND_JUMP_SIZE;
	}

#ifdef __CODEGENX86_32BIT
	__DEF_INSTR_1(jcxz, p, __PTR)
	{
		int32_t diff;
		if (!wr)
			return 10;
		diff = (int32_t)((size_t)a - ((size_t)__EXEC_OFFSET(3)));
		if ((diff >= -0x80) && (diff <= 0x7f))
		{
			__WRITE_BUF_8_8(0, 0x67, 0xe3);
			__WRITE_BUF_8(2, (int8_t)diff);
			return 3;
		}
		else
		{
			__WRITE_BUF_8_8_8_8(0, 0x67, 0xe3, 2, 0xeb);
			__WRITE_BUF_8_8(4, 5, 0xe9);
			__WRITE_BUF_32(6, (int32_t)((size_t)a - ((size_t)__EXEC_OFFSET(10))));
			return 10;
		}
	}

	__DEF_INSTR_1(jcxz, t, __TARGET)
	{
		if (a->addr != 0)
			return __NAME(jcxz, p) (__CONTEXT, a->addr);
		if (wr)
			__PREFIX(add_label_ref) (a, buf, __JUMPTARGET_JCXZ  __CGX86_ASSERT_PARAMS);
		return a->nearJump ? __FORWARD_REF_JCXZ_NEAR_JUMP_SIZE : __FORWARD_REF_JCXZ_JUMP_SIZE;
	}
#endif

	__DEF_INSTR_1(jecxz, p, __PTR)
	{
#ifdef __CODEGENX86_32BIT
		int32_t diff;
		if (!wr)
			return 9;
		diff = (int32_t)((size_t)a - ((size_t)__EXEC_OFFSET(2)));
		if ((diff >= -0x80) && (diff <= 0x7f))
		{
			__WRITE_BUF_8(0, 0xe3);
			__WRITE_BUF_8(1, (int8_t)diff);
			return 2;
		}
		else
		{
			__WRITE_BUF_8_8_8_8(0, 0xe3, 2, 0xeb, 5);
			__WRITE_BUF_8(4, 0xe9);
			__WRITE_BUF_32(5, (int32_t)((size_t)a - ((size_t)__EXEC_OFFSET(9))));
			return 9;
		}
#else
		int64_t diff;
		if (!wr)
			return 19;
		diff = (int64_t)((size_t)a - ((size_t)__EXEC_OFFSET(3)));
		if ((diff >= -0x80) && (diff <= 0x7f))
		{
			__WRITE_BUF_8_8(0, 0x67, 0xe3);
			__WRITE_BUF_8(2, (int8_t)diff);
			return 3;
		}
		diff = (int64_t)((size_t)a - ((size_t)__EXEC_OFFSET(10)));
		if ((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL))
		{
			__WRITE_BUF_8_8_8_8(0, 0x67, 0xe3, 2, 0xeb);
			__WRITE_BUF_8_8(4, 5, 0xe9);
			__WRITE_BUF_32(6, (int32_t)diff);
			return 10;
		}
		else
		{
			__WRITE_BUF_8_8_8_8(0, 0x67, 0xe3, 2, 0xeb);
			__WRITE_BUF_8_8(4, 14, 0xff);
			__WRITE_BUF_8(6, 0x25);
			__WRITE_BUF_32(7, 0);
			__WRITE_BUF_64(11, (uint64_t)(size_t)a);
			return 19;
		}
#endif
	}

	__DEF_INSTR_1(jecxz, t, __TARGET)
	{
		if (a->addr != 0)
			return __NAME(jecxz, p) (__CONTEXT, a->addr);
		if (wr)
			__PREFIX(add_label_ref) (a, buf, __JUMPTARGET_JECXZ  __CGX86_ASSERT_PARAMS);
		return a->nearJump ? __FORWARD_REF_JCXZ_NEAR_JUMP_SIZE : __FORWARD_REF_JCXZ_JUMP_SIZE;
	}

#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_1(jrcxz, p, __PTR)
	{
		int64_t diff;
		if (!wr)
			return 18;
		diff = (int64_t)((size_t)a - ((size_t)__EXEC_OFFSET(2)));
		if ((diff >= -0x80) && (diff <= 0x7f))
		{
			__WRITE_BUF_8(0, 0xe3);
			__WRITE_BUF_8(1, (int8_t)diff);
			return 2;
		}
		diff = (int64_t)((size_t)a - ((size_t)__EXEC_OFFSET(9)));
		if ((diff >= -0x80000000LL) && (diff <= 0x7fffffffLL))
		{
			__WRITE_BUF_8_8_8_8(0, 0xe3, 2, 0xeb, 5);
			__WRITE_BUF_8(4, 0xe9);
			__WRITE_BUF_32(5, (int32_t)diff);
			return 9;
		}
		else
		{
			__WRITE_BUF_8_8_8_8(0, 0xe3, 2, 0xeb, 14);
			__WRITE_BUF_8_8(4, 0xff, 0x25);
			__WRITE_BUF_32(6, 0);
			__WRITE_BUF_64(10, (uint64_t)(size_t)a);
			return 18;
		}
	}

	__DEF_INSTR_1(jrcxz, t, __TARGET)
	{
		if (a->addr != 0)
			return __NAME(jrcxz, p) (__CONTEXT, a->addr);
		if (wr)
			__PREFIX(add_label_ref) (a, buf, __JUMPTARGET_JRCXZ  __CGX86_ASSERT_PARAMS);
		return a->nearJump ? __FORWARD_REF_JCXZ_NEAR_JUMP_SIZE : __FORWARD_REF_JCXZ_JUMP_SIZE;
	}
#endif

#ifdef __CODEGENX86_32BIT
	__DEF_INSTR_1(calln, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xff, 2, __reg32(a)); }
	__DEF_INSTR_1(jmpn, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xff, 4, __reg32(a)); }
#else
	__DEF_INSTR_1(calln, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xff, 2, __reg64(a)); }
	__DEF_INSTR_1(jmpn, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xff, 4, __reg64(a)); }
#endif
	__DEF_INSTR_1(calln, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xff, 2, __MEMOP(a), 0); }
	__DEF_INSTR_1(callf, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xff, 3, __MEMOP(a), 0); }
	__DEF_INSTR_1(jmpn, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xff, 4, __MEMOP(a), 0); }
	__DEF_INSTR_1(jmpf, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xff, 5, __MEMOP(a), 0); }

#define __CONDJUMP_INSTR(n, cond) \
	__DEF_INSTR_1(n, p, __PTR) { return __NAME(condjmp, p) (__CONTEXT, cond, a); } \
	__DEF_INSTR_1(n, t, __TARGET) { return __NAME(condjmp, t) (__CONTEXT, cond, a); }

	__CONDJUMP_INSTR(jo, 0)
	__CONDJUMP_INSTR(jno, 1)
	__CONDJUMP_INSTR(jb, 2)
	__CONDJUMP_INSTR(jc, 2)
	__CONDJUMP_INSTR(jnae, 2)
	__CONDJUMP_INSTR(jae, 3)
	__CONDJUMP_INSTR(jnb, 3)
	__CONDJUMP_INSTR(jnc, 3)
	__CONDJUMP_INSTR(je, 4)
	__CONDJUMP_INSTR(jz, 4)
	__CONDJUMP_INSTR(jne, 5)
	__CONDJUMP_INSTR(jnz, 5)
	__CONDJUMP_INSTR(jbe, 6)
	__CONDJUMP_INSTR(jna, 6)
	__CONDJUMP_INSTR(ja, 7)
	__CONDJUMP_INSTR(jnbe, 7)
	__CONDJUMP_INSTR(js, 8)
	__CONDJUMP_INSTR(jns, 9)
	__CONDJUMP_INSTR(jpe, 10)
	__CONDJUMP_INSTR(jp, 10)
	__CONDJUMP_INSTR(jpo, 11)
	__CONDJUMP_INSTR(jnp, 11)
	__CONDJUMP_INSTR(jl, 12)
	__CONDJUMP_INSTR(jnge, 12)
	__CONDJUMP_INSTR(jge, 13)
	__CONDJUMP_INSTR(jnl, 13)
	__CONDJUMP_INSTR(jle, 14)
	__CONDJUMP_INSTR(jng, 14)
	__CONDJUMP_INSTR(jg, 15)
	__CONDJUMP_INSTR(jnle, 15)


	// Conditional move instructions
	__DEF_INSTR_2_ARG(condmov_16, rr, __REG, __REG, uint8_t cond) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0x40 + cond, __reg16(a), __reg16(b)); }
	__DEF_INSTR_2_ARG(condmov_16, rm, __REG, __MEM, uint8_t cond) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0x40 + cond, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2_ARG(condmov_32, rr, __REG, __REG, uint8_t cond) { return __MODRM(reg_twobyte) (__CONTEXT, 0x40 + cond, __reg32(a), __reg32(b)); }
	__DEF_INSTR_2_ARG(condmov_32, rm, __REG, __MEM, uint8_t cond) { return __MODRM(mem_twobyte) (__CONTEXT, 0x40 + cond, __reg32(a), __MEMOP(b), 0); }

#define __CONDMOV_INSTR(n, cond) \
	__DEF_INSTR_2(n ## _16, rr, __REG, __REG) { return __NAME(condmov_16, rr) (__CONTEXT, cond, a, b); } \
	__DEF_INSTR_2(n ## _16, rm, __REG, __MEM) { return __NAME(condmov_16, rm) (__CONTEXT, cond, a, __MEMOP(b)); } \
	__DEF_INSTR_2(n ## _32, rr, __REG, __REG) { return __NAME(condmov_32, rr) (__CONTEXT, cond, a, b); } \
	__DEF_INSTR_2(n ## _32, rm, __REG, __MEM) { return __NAME(condmov_32, rm) (__CONTEXT, cond, a, __MEMOP(b)); }

	__CONDMOV_INSTR(cmovo, 0)
	__CONDMOV_INSTR(cmovno, 1)
	__CONDMOV_INSTR(cmovb, 2)
	__CONDMOV_INSTR(cmovc, 2)
	__CONDMOV_INSTR(cmovnae, 2)
	__CONDMOV_INSTR(cmovae, 3)
	__CONDMOV_INSTR(cmovnb, 3)
	__CONDMOV_INSTR(cmovnc, 3)
	__CONDMOV_INSTR(cmove, 4)
	__CONDMOV_INSTR(cmovz, 4)
	__CONDMOV_INSTR(cmovne, 5)
	__CONDMOV_INSTR(cmovnz, 5)
	__CONDMOV_INSTR(cmovbe, 6)
	__CONDMOV_INSTR(cmovna, 6)
	__CONDMOV_INSTR(cmova, 7)
	__CONDMOV_INSTR(cmovnbe, 7)
	__CONDMOV_INSTR(cmovs, 8)
	__CONDMOV_INSTR(cmovns, 9)
	__CONDMOV_INSTR(cmovpe, 10)
	__CONDMOV_INSTR(cmovp, 10)
	__CONDMOV_INSTR(cmovpo, 11)
	__CONDMOV_INSTR(cmovnp, 11)
	__CONDMOV_INSTR(cmovl, 12)
	__CONDMOV_INSTR(cmovnge, 12)
	__CONDMOV_INSTR(cmovge, 13)
	__CONDMOV_INSTR(cmovnl, 13)
	__CONDMOV_INSTR(cmovle, 14)
	__CONDMOV_INSTR(cmovng, 14)
	__CONDMOV_INSTR(cmovg, 15)
	__CONDMOV_INSTR(cmovnle, 15)

#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2_ARG(condmov_64, rr, __REG, __REG, uint8_t cond) { return __MODRM(reg_twobyte64) (__CONTEXT, 0x40 + cond, __reg64(a), __reg64(b)); }
	__DEF_INSTR_2_ARG(condmov_64, rm, __REG, __MEM, uint8_t cond) { return __MODRM(mem_twobyte64) (__CONTEXT, 0x40 + cond, __reg64(a), __MEMOP(b), 0); }

#define __CONDMOV_INSTR_64(n, cond) \
	__DEF_INSTR_2(n ## _64, rr, __REG, __REG) { return __NAME(condmov_64, rr) (__CONTEXT, cond, a, b); } \
	__DEF_INSTR_2(n ## _64, rm, __REG, __MEM) { return __NAME(condmov_64, rm) (__CONTEXT, cond, a, __MEMOP(b)); } \

	__CONDMOV_INSTR_64(cmovo, 0)
	__CONDMOV_INSTR_64(cmovno, 1)
	__CONDMOV_INSTR_64(cmovb, 2)
	__CONDMOV_INSTR_64(cmovc, 2)
	__CONDMOV_INSTR_64(cmovnae, 2)
	__CONDMOV_INSTR_64(cmovae, 3)
	__CONDMOV_INSTR_64(cmovnb, 3)
	__CONDMOV_INSTR_64(cmovnc, 3)
	__CONDMOV_INSTR_64(cmove, 4)
	__CONDMOV_INSTR_64(cmovz, 4)
	__CONDMOV_INSTR_64(cmovne, 5)
	__CONDMOV_INSTR_64(cmovnz, 5)
	__CONDMOV_INSTR_64(cmovbe, 6)
	__CONDMOV_INSTR_64(cmovna, 6)
	__CONDMOV_INSTR_64(cmova, 7)
	__CONDMOV_INSTR_64(cmovnbe, 7)
	__CONDMOV_INSTR_64(cmovs, 8)
	__CONDMOV_INSTR_64(cmovns, 9)
	__CONDMOV_INSTR_64(cmovpe, 10)
	__CONDMOV_INSTR_64(cmovp, 10)
	__CONDMOV_INSTR_64(cmovpo, 11)
	__CONDMOV_INSTR_64(cmovnp, 11)
	__CONDMOV_INSTR_64(cmovl, 12)
	__CONDMOV_INSTR_64(cmovnge, 12)
	__CONDMOV_INSTR_64(cmovge, 13)
	__CONDMOV_INSTR_64(cmovnl, 13)
	__CONDMOV_INSTR_64(cmovle, 14)
	__CONDMOV_INSTR_64(cmovng, 14)
	__CONDMOV_INSTR_64(cmovg, 15)
	__CONDMOV_INSTR_64(cmovnle, 15)

#endif


	// Set to condition instructions
	__DEF_INSTR_1_ARG(setcond, r, __REG, uint8_t cond) { return __MODRM(reg_twobyte) (__CONTEXT, 0x90 + cond, 0, __reg8(a)); }
	__DEF_INSTR_1_ARG(setcond, m, __MEM, uint8_t cond) { return __MODRM(mem_twobyte) (__CONTEXT, 0x90 + cond, 0, __MEMOP(a), 0); }

#define __SETCOND_INSTR(n, cond) \
	__DEF_INSTR_1(n, r, __REG) { return __NAME(setcond, r) (__CONTEXT, cond, a); } \
	__DEF_INSTR_1(n, m, __MEM) { return __NAME(setcond, m) (__CONTEXT, cond, __MEMOP(a)); }

	__SETCOND_INSTR(seto, 0)
	__SETCOND_INSTR(setno, 1)
	__SETCOND_INSTR(setb, 2)
	__SETCOND_INSTR(setc, 2)
	__SETCOND_INSTR(setnae, 2)
	__SETCOND_INSTR(setae, 3)
	__SETCOND_INSTR(setnb, 3)
	__SETCOND_INSTR(setnc, 3)
	__SETCOND_INSTR(sete, 4)
	__SETCOND_INSTR(setz, 4)
	__SETCOND_INSTR(setne, 5)
	__SETCOND_INSTR(setnz, 5)
	__SETCOND_INSTR(setbe, 6)
	__SETCOND_INSTR(setna, 6)
	__SETCOND_INSTR(seta, 7)
	__SETCOND_INSTR(setnbe, 7)
	__SETCOND_INSTR(sets, 8)
	__SETCOND_INSTR(setns, 9)
	__SETCOND_INSTR(setpe, 10)
	__SETCOND_INSTR(setp, 10)
	__SETCOND_INSTR(setpo, 11)
	__SETCOND_INSTR(setnp, 11)
	__SETCOND_INSTR(setl, 12)
	__SETCOND_INSTR(setnge, 12)
	__SETCOND_INSTR(setge, 13)
	__SETCOND_INSTR(setnl, 13)
	__SETCOND_INSTR(setle, 14)
	__SETCOND_INSTR(setng, 14)
	__SETCOND_INSTR(setg, 15)
	__SETCOND_INSTR(setnle, 15)


	// ALU instructions
	__DEF_INSTR_2_ARG(alu_8, rr, __REG, __REG, uint8_t op) { return __MODRM(reg_onebyte) (__CONTEXT, (op << 3) + 2, __reg8(a), __reg8(b)); }
	__DEF_INSTR_2_ARG(alu_8, rm, __REG, __MEM, uint8_t op) { return __MODRM(mem_onebyte) (__CONTEXT, (op << 3) + 2, __reg8(a), __MEMOP(b), 0); }
	__DEF_INSTR_2_ARG(alu_8, mr, __MEM, __REG, uint8_t op) { return __MODRM(mem_onebyte) (__CONTEXT, op << 3, __reg8(b), __MEMOP(a), 0); }
	__DEF_INSTR_2_ARG(alu_8, mi, __MEM, __IMM8, uint8_t op) { return __MODRM(mem_onebyte_imm8) (__CONTEXT, 0x80, op, __MEMOP(a), b); }
	__DEF_INSTR_2_ARG(alu_16, rr, __REG, __REG, uint8_t op) { return __MODRM(reg_onebyte_opsz) (__CONTEXT, (op << 3) + 3, __reg16(a), __reg16(b)); }
	__DEF_INSTR_2_ARG(alu_16, rm, __REG, __MEM, uint8_t op) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, (op << 3) + 3, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2_ARG(alu_16, mr, __MEM, __REG, uint8_t op) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, (op << 3) + 1, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_2_ARG(alu_32, rr, __REG, __REG, uint8_t op) { return __MODRM(reg_onebyte) (__CONTEXT, (op << 3) + 3, __reg32(a), __reg32(b)); }
	__DEF_INSTR_2_ARG(alu_32, rm, __REG, __MEM, uint8_t op) { return __MODRM(mem_onebyte) (__CONTEXT, (op << 3) + 3, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2_ARG(alu_32, mr, __MEM, __REG, uint8_t op) { return __MODRM(mem_onebyte) (__CONTEXT, (op << 3) + 1, __reg32(b), __MEMOP(a), 0); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2_ARG(alu_64, rr, __REG, __REG, uint8_t op) { return __MODRM(reg_onebyte64) (__CONTEXT, (op << 3) + 3, __reg64(a), __reg64(b)); }
	__DEF_INSTR_2_ARG(alu_64, rm, __REG, __MEM, uint8_t op) { return __MODRM(mem_onebyte64) (__CONTEXT, (op << 3) + 3, __reg64(a), __MEMOP(b), 0); }
	__DEF_INSTR_2_ARG(alu_64, mr, __MEM, __REG, uint8_t op) { return __MODRM(mem_onebyte64) (__CONTEXT, (op << 3) + 1, __reg64(b), __MEMOP(a), 0); }
#endif

	__DEF_INSTR_2_ARG(alu_8, ri, __REG, __IMM8, uint8_t op)
	{
		if (a == REG_AL)
			return __onebyte_imm8(__CONTEXT, (op << 3) + 4, b);
		return __MODRM(reg_onebyte_imm8) (__CONTEXT, 0x80, op, __reg8(a), b);
	}

	__DEF_INSTR_2_ARG(alu_16, ri, __REG, __IMM16, uint8_t op)
	{
		if (a == REG_AX)
			return __onebyte_opsz_imm16(__CONTEXT, (op << 3) + 5, b);
		if ((b >= -0x80) && (b <= 0x7f))
			return __MODRM(reg_onebyte_opsz_imm8) (__CONTEXT, 0x83, op, __reg16(a), (int8_t)b);
		return __MODRM(reg_onebyte_opsz_imm16) (__CONTEXT, 0x81, op, __reg16(a), b);
	}

	__DEF_INSTR_2_ARG(alu_16, mi, __MEM, __IMM16, uint8_t op)
	{
		if ((b >= -0x80) && (b <= 0x7f))
			return __MODRM(mem_onebyte_opsz_imm8) (__CONTEXT, 0x83, op, __MEMOP(a), (int8_t)b);
		return __MODRM(mem_onebyte_opsz_imm16) (__CONTEXT, 0x81, op, __MEMOP(a), b);
	}

	__DEF_INSTR_2_ARG(alu_32, ri, __REG, __IMM32, uint8_t op)
	{
		if ((b >= -0x80) && (b <= 0x7f))
			return __MODRM(reg_onebyte_imm8) (__CONTEXT, 0x83, op, __reg32(a), (int8_t)b);
		if (a == REG_EAX)
			return __onebyte_imm32(__CONTEXT, (op << 3) + 5, b);
		return __MODRM(reg_onebyte_imm32) (__CONTEXT, 0x81, op, __reg32(a), b);
	}

	__DEF_INSTR_2_ARG(alu_32, mi, __MEM, __IMM32, uint8_t op)
	{
		if ((b >= -0x80) && (b <= 0x7f))
			return __MODRM(mem_onebyte_imm8) (__CONTEXT, 0x83, op, __MEMOP(a), (int8_t)b);
		return __MODRM(mem_onebyte_imm32) (__CONTEXT, 0x81, op, __MEMOP(a), b);
	}

#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2_ARG(alu_64, ri, __REG, __IMM32, uint8_t op)
	{
		if ((b >= -0x80) && (b <= 0x7f))
			return __MODRM(reg_onebyte64_imm8) (__CONTEXT, 0x83, op, __reg64(a), (int8_t)b);
		if (a == REG_RAX)
			return __onebyte64_imm32(__CONTEXT, (op << 3) + 5, b);
		return __MODRM(reg_onebyte64_imm32) (__CONTEXT, 0x81, op, __reg64(a), b);
	}

	__DEF_INSTR_2_ARG(alu_64, mi, __MEM, __IMM32, uint8_t op)
	{
		if ((b >= -0x80) && (b <= 0x7f))
			return __MODRM(mem_onebyte64_imm8) (__CONTEXT, 0x83, op, __MEMOP(a), (int8_t)b);
		return __MODRM(mem_onebyte64_imm32) (__CONTEXT, 0x81, op, __MEMOP(a), b);
	}
#endif

#define __ALU_INSTR_NO_LOCK(n, o) \
	__DEF_INSTR_2(n ## _8, rr, __REG, __REG) { return __NAME(alu_8, rr) (__CONTEXT, o, a, b); } \
	__DEF_INSTR_2(n ## _8, rm, __REG, __MEM) { return __NAME(alu_8, rm) (__CONTEXT, o, a, __MEMOP(b)); } \
	__DEF_INSTR_2(n ## _8, mr, __MEM, __REG) { return __NAME(alu_8, mr) (__CONTEXT, o, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _8, ri, __REG, __IMM8) { return __NAME(alu_8, ri) (__CONTEXT, o, a, b); } \
	__DEF_INSTR_2(n ## _8, mi, __MEM, __IMM8) { return __NAME(alu_8, mi) (__CONTEXT, o, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _16, rr, __REG, __REG) { return __NAME(alu_16, rr) (__CONTEXT, o, a, b); } \
	__DEF_INSTR_2(n ## _16, rm, __REG, __MEM) { return __NAME(alu_16, rm) (__CONTEXT, o, a, __MEMOP(b)); } \
	__DEF_INSTR_2(n ## _16, mr, __MEM, __REG) { return __NAME(alu_16, mr) (__CONTEXT, o, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _16, ri, __REG, __IMM16) { return __NAME(alu_16, ri) (__CONTEXT, o, a, b); } \
	__DEF_INSTR_2(n ## _16, mi, __MEM, __IMM16) { return __NAME(alu_16, mi) (__CONTEXT, o, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _32, rr, __REG, __REG) { return __NAME(alu_32, rr) (__CONTEXT, o, a, b); } \
	__DEF_INSTR_2(n ## _32, rm, __REG, __MEM) { return __NAME(alu_32, rm) (__CONTEXT, o, a, __MEMOP(b)); } \
	__DEF_INSTR_2(n ## _32, mr, __MEM, __REG) { return __NAME(alu_32, mr) (__CONTEXT, o, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _32, ri, __REG, __IMM32) { return __NAME(alu_32, ri) (__CONTEXT, o, a, b); } \
	__DEF_INSTR_2(n ## _32, mi, __MEM, __IMM32) { return __NAME(alu_32, mi) (__CONTEXT, o, __MEMOP(a), b); } \

#define __ALU_INSTR(n, o) \
	__ALU_INSTR_NO_LOCK(n, o) \
	__DEF_INSTR_2(lock_ ## n ## _8, mr, __MEM, __REG) { return __LOCKPREFIX(__NAME(alu_8, mr) (__CONTEXT_OFFSET(1), o, __MEMOP(a), b)); } \
	__DEF_INSTR_2(lock_ ## n ## _8, mi, __MEM, __IMM8) { return __LOCKPREFIX(__NAME(alu_8, mi) (__CONTEXT_OFFSET(1), o, __MEMOP(a), b)); } \
	__DEF_INSTR_2(lock_ ## n ## _16, mr, __MEM, __REG) { return __LOCKPREFIX(__NAME(alu_16, mr) (__CONTEXT_OFFSET(1), o, __MEMOP(a), b)); } \
	__DEF_INSTR_2(lock_ ## n ## _16, mi, __MEM, __IMM16) { return __LOCKPREFIX(__NAME(alu_16, mi) (__CONTEXT_OFFSET(1), o, __MEMOP(a), b)); } \
	__DEF_INSTR_2(lock_ ## n ## _32, mr, __MEM, __REG) { return __LOCKPREFIX(__NAME(alu_32, mr) (__CONTEXT_OFFSET(1), o, __MEMOP(a), b)); } \
	__DEF_INSTR_2(lock_ ## n ## _32, mi, __MEM, __IMM32) { return __LOCKPREFIX(__NAME(alu_32, mi) (__CONTEXT_OFFSET(1), o, __MEMOP(a), b)); }

	__ALU_INSTR(add, 0)
	__ALU_INSTR(or, 1)
	__ALU_INSTR(adc, 2)
	__ALU_INSTR(sbb, 3)
	__ALU_INSTR(and, 4)
	__ALU_INSTR(sub, 5)
	__ALU_INSTR(xor, 6)
	__ALU_INSTR_NO_LOCK(cmp, 7)

#ifdef __CODEGENX86_64BIT

#define __ALU_INSTR_64_NO_LOCK(n, o) \
	__DEF_INSTR_2(n ## _64, rr, __REG, __REG) { return __NAME(alu_64, rr) (__CONTEXT, o, a, b); } \
	__DEF_INSTR_2(n ## _64, rm, __REG, __MEM) { return __NAME(alu_64, rm) (__CONTEXT, o, a, __MEMOP(b)); } \
	__DEF_INSTR_2(n ## _64, mr, __MEM, __REG) { return __NAME(alu_64, mr) (__CONTEXT, o, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _64, ri, __REG, __IMM32) { return __NAME(alu_64, ri) (__CONTEXT, o, a, b); } \
	__DEF_INSTR_2(n ## _64, mi, __MEM, __IMM32) { return __NAME(alu_64, mi) (__CONTEXT, o, __MEMOP(a), b); }

#define __ALU_INSTR_64(n, o) \
	__ALU_INSTR_64_NO_LOCK(n, o) \
	__DEF_INSTR_2(lock_ ## n ## _64, mr, __MEM, __REG) { return __LOCKPREFIX(__NAME(alu_64, mr) (__CONTEXT_OFFSET(1), o, __MEMOP(a), b)); } \
	__DEF_INSTR_2(lock_ ## n ## _64, mi, __MEM, __IMM32) { return __LOCKPREFIX(__NAME(alu_64, mi) (__CONTEXT_OFFSET(1), o, __MEMOP(a), b)); }

	__ALU_INSTR_64(add, 0)
	__ALU_INSTR_64(or, 1)
	__ALU_INSTR_64(adc, 2)
	__ALU_INSTR_64(sbb, 3)
	__ALU_INSTR_64(and, 4)
	__ALU_INSTR_64(sub, 5)
	__ALU_INSTR_64(xor, 6)
	__ALU_INSTR_64_NO_LOCK(cmp, 7)

#endif


	// Push/pop instructions
	__DEF_INSTR_1(push, r, __REG)
	{
		if (a == REG_ES) return __onebyte(__CONTEXT, 0x06);
		if (a == REG_CS) return __onebyte(__CONTEXT, 0x0e);
		if (a == REG_SS) return __onebyte(__CONTEXT, 0x16);
		if (a == REG_DS) return __onebyte(__CONTEXT, 0x1e);
		if (a == REG_FS) return __twobyte(__CONTEXT, 0xa0);
		if (a == REG_GS) return __twobyte(__CONTEXT, 0xa8);
#ifdef __CODEGENX86_32BIT
		return __onebyte_opreg(__CONTEXT, 0x50, __reg32(a));
#else
		return __onebyte_opreg(__CONTEXT, 0x50, __reg64(a));
#endif
	}

	__DEF_INSTR_1(push, i, __IMM32)
	{
		if ((a >= -0x80) && (a <= 0x7f))
			return __onebyte_imm8(__CONTEXT, 0x6a, (int8_t)a);
		return __onebyte_imm32(__CONTEXT, 0x68, a);
	}

	__DEF_INSTR_1(pop, r, __REG)
	{
		if (a == REG_ES) return __onebyte(__CONTEXT, 0x07);
		if (a == REG_SS) return __onebyte(__CONTEXT, 0x17);
		if (a == REG_DS) return __onebyte(__CONTEXT, 0x1f);
		if (a == REG_FS) return __twobyte(__CONTEXT, 0xa1);
		if (a == REG_GS) return __twobyte(__CONTEXT, 0xa9);
#ifdef __CODEGENX86_32BIT
		return __onebyte_opreg(__CONTEXT, 0x58, __reg32(a));
#else
		return __onebyte_opreg(__CONTEXT, 0x58, __reg64(a));
#endif
	}

	__DEF_INSTR_1(push, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xff, 6, __MEMOP(a), 0); }
	__DEF_INSTR_1(pop, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0x8f, 0, __MEMOP(a), 0); }
	__ONEBYTE_INSTR(pushad, 0x60)
	__ONEBYTE_INSTR(popad, 0x61)
#ifdef __CODEGENX86_32BIT
	__ONEBYTE_INSTR(pushfd, 0x9c)
	__ONEBYTE_INSTR(popfd, 0x9d)
#else
	__ONEBYTE_INSTR(pushfq, 0x9c)
	__ONEBYTE_INSTR(popfq, 0x9d)
#endif


	// Inc/dec instructions
	__DEF_INSTR_1(inc_8, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xfe, 0, __reg8(a)); }
	__DEF_INSTR_1(inc_8, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xfe, 0, __MEMOP(a), 0); }
	__DEF_INSTR_1(inc_16, m, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xff, 0, __MEMOP(a), 0); }
	__DEF_INSTR_1(inc_32, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xff, 0, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_inc_8, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0xfe, 0, __MEMOP(a), 0)); }
	__DEF_INSTR_1(lock_inc_16, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte_opsz) (__CONTEXT_OFFSET(1), 0xff, 0, __MEMOP(a), 0)); }
	__DEF_INSTR_1(lock_inc_32, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0xff, 0, __MEMOP(a), 0)); }
	__DEF_INSTR_1(dec_8, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xfe, 1, __reg8(a)); }
	__DEF_INSTR_1(dec_8, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xfe, 1, __MEMOP(a), 0); }
	__DEF_INSTR_1(dec_16, m, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xff, 1, __MEMOP(a), 0); }
	__DEF_INSTR_1(dec_32, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xff, 1, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_dec_8, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0xfe, 1, __MEMOP(a), 0)); }
	__DEF_INSTR_1(lock_dec_16, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte_opsz) (__CONTEXT_OFFSET(1), 0xff, 1, __MEMOP(a), 0)); }
	__DEF_INSTR_1(lock_dec_32, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0xff, 1, __MEMOP(a), 0)); }
#ifdef __CODEGENX86_32BIT
	__DEF_INSTR_1(inc_16, r, __REG) { return __onebyte_opsz(__CONTEXT, 0x40 + __reg16(a)); }
	__DEF_INSTR_1(inc_32, r, __REG) { return __onebyte(__CONTEXT, 0x40 + __reg32(a)); }
	__DEF_INSTR_1(dec_16, r, __REG) { return __onebyte_opsz(__CONTEXT, 0x48 + __reg16(a)); }
	__DEF_INSTR_1(dec_32, r, __REG) { return __onebyte(__CONTEXT, 0x48 + __reg32(a)); }
#else
	__DEF_INSTR_1(inc_16, r, __REG) { return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0xff, 0, __reg16(a)); }
	__DEF_INSTR_1(inc_32, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xff, 0, __reg32(a)); }
	__DEF_INSTR_1(inc_64, r, __REG) { return __MODRM(reg_onebyte64) (__CONTEXT, 0xff, 0, __reg64(a)); }
	__DEF_INSTR_1(inc_64, m, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0xff, 0, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_inc_64, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte64) (__CONTEXT_OFFSET(1), 0xff, 0, __MEMOP(a), 0)); }
	__DEF_INSTR_1(dec_16, r, __REG) { return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0xff, 1, __reg16(a)); }
	__DEF_INSTR_1(dec_32, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xff, 1, __reg32(a)); }
	__DEF_INSTR_1(dec_64, r, __REG) { return __MODRM(reg_onebyte64) (__CONTEXT, 0xff, 1, __reg64(a)); }
	__DEF_INSTR_1(dec_64, m, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0xff, 1, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_dec_64, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte64) (__CONTEXT_OFFSET(1), 0xff, 1, __MEMOP(a), 0)); }
#endif


	// Multiply/divide instructions
	__DEF_INSTR_3(imul_16, rri, __REG, __REG, __IMM16)
	{
		if ((c >= -0x80) && (c <= 0x7f))
			return __MODRM(reg_onebyte_opsz_imm8) (__CONTEXT, 0x6b, __reg16(a), __reg16(b), (int8_t)c);
		return __MODRM(reg_onebyte_opsz_imm16) (__CONTEXT, 0x69, __reg16(a), __reg16(b), c);
	}

	__DEF_INSTR_3(imul_16, rmi, __REG, __MEM, __IMM16)
	{
		if ((c >= -0x80) && (c <= 0x7f))
			return __MODRM(mem_onebyte_opsz_imm8) (__CONTEXT, 0x6b, __reg16(a), __MEMOP(b), (int8_t)c);
		return __MODRM(mem_onebyte_opsz_imm16) (__CONTEXT, 0x69, __reg16(a), __MEMOP(b), c);
	}

	__DEF_INSTR_3(imul_32, rri, __REG, __REG, __IMM32)
	{
		if ((c >= -0x80) && (c <= 0x7f))
			return __MODRM(reg_onebyte_imm8) (__CONTEXT, 0x6b, __reg32(a), __reg32(b), (int8_t)c);
		return __MODRM(reg_onebyte_imm32) (__CONTEXT, 0x69, __reg32(a), __reg32(b), c);
	}

	__DEF_INSTR_3(imul_32, rmi, __REG, __MEM, __IMM32)
	{
		if ((c >= -0x80) && (c <= 0x7f))
			return __MODRM(mem_onebyte_imm8) (__CONTEXT, 0x6b, __reg32(a), __MEMOP(b), (int8_t)c);
		return __MODRM(mem_onebyte_imm32) (__CONTEXT, 0x69, __reg32(a), __MEMOP(b), c);
	}

#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_3(imul_64, rri, __REG, __REG, __IMM32)
	{
		if ((c >= -0x80) && (c <= 0x7f))
			return __MODRM(reg_onebyte64_imm8) (__CONTEXT, 0x6b, __reg64(a), __reg64(b), (int8_t)c);
		return __MODRM(reg_onebyte64_imm32) (__CONTEXT, 0x69, __reg64(a), __reg64(b), c);
	}

	__DEF_INSTR_3(imul_64, rmi, __REG, __MEM, __IMM32)
	{
		if ((c >= -0x80) && (c <= 0x7f))
			return __MODRM(mem_onebyte64_imm8) (__CONTEXT, 0x6b, __reg64(a), __MEMOP(b), (int8_t)c);
		return __MODRM(mem_onebyte64_imm32) (__CONTEXT, 0x69, __reg64(a), __MEMOP(b), c);
	}
#endif

	__DEF_INSTR_1(imul_8, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf6, 5, __reg8(a)); }
	__DEF_INSTR_1(imul_8, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf6, 5, __MEMOP(a), 0); }
	__DEF_INSTR_1(imul_16, r, __REG) { return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0xf7, 5, __reg16(a)); }
	__DEF_INSTR_1(imul_16, m, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xf7, 5, __MEMOP(a), 0); }
	__DEF_INSTR_2(imul_16, rr, __REG, __REG) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xaf, __reg16(a), __reg16(b)); }
	__DEF_INSTR_2(imul_16, rm, __REG, __MEM) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xaf, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(imul_16, ri, __REG, __IMM16) { return __NAME(imul_16, rri) (__CONTEXT, a, a, b); }
	__DEF_INSTR_1(imul_32, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf7, 5, __reg32(a)); }
	__DEF_INSTR_1(imul_32, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf7, 5, __MEMOP(a), 0); }
	__DEF_INSTR_2(imul_32, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xaf, __reg32(a), __reg32(b)); }
	__DEF_INSTR_2(imul_32, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0xaf, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(imul_32, ri, __REG, __IMM16) { return __NAME(imul_32, rri) (__CONTEXT, a, a, b); }
	__DEF_INSTR_1(mul_8, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf6, 4, __reg8(a)); }
	__DEF_INSTR_1(mul_8, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf6, 4, __MEMOP(a), 0); }
	__DEF_INSTR_1(mul_16, r, __REG) { return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0xf7, 4, __reg16(a)); }
	__DEF_INSTR_1(mul_16, m, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xf7, 4, __MEMOP(a), 0); }
	__DEF_INSTR_1(mul_32, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf7, 4, __reg32(a)); }
	__DEF_INSTR_1(mul_32, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf7, 4, __MEMOP(a), 0); }
	__DEF_INSTR_1(idiv_8, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf6, 7, __reg8(a)); }
	__DEF_INSTR_1(idiv_8, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf6, 7, __MEMOP(a), 0); }
	__DEF_INSTR_1(idiv_16, r, __REG) { return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0xf7, 7, __reg16(a)); }
	__DEF_INSTR_1(idiv_16, m, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xf7, 7, __MEMOP(a), 0); }
	__DEF_INSTR_1(idiv_32, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf7, 7, __reg32(a)); }
	__DEF_INSTR_1(idiv_32, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf7, 7, __MEMOP(a), 0); }
	__DEF_INSTR_1(div_8, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf6, 6, __reg8(a)); }
	__DEF_INSTR_1(div_8, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf6, 6, __MEMOP(a), 0); }
	__DEF_INSTR_1(div_16, r, __REG) { return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0xf7, 6, __reg16(a)); }
	__DEF_INSTR_1(div_16, m, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xf7, 6, __MEMOP(a), 0); }
	__DEF_INSTR_1(div_32, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf7, 6, __reg32(a)); }
	__DEF_INSTR_1(div_32, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf7, 6, __MEMOP(a), 0); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_1(imul_64, r, __REG) { return __MODRM(reg_onebyte64) (__CONTEXT, 0xf7, 5, __reg64(a)); }
	__DEF_INSTR_1(imul_64, m, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0xf7, 5, __MEMOP(a), 0); }
	__DEF_INSTR_2(imul_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xaf, __reg64(a), __reg64(b)); }
	__DEF_INSTR_2(imul_64, rm, __REG, __MEM) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xaf, __reg64(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(imul_64, ri, __REG, __IMM16) { return __NAME(imul_64, rri) (__CONTEXT, a, a, b); }
	__DEF_INSTR_1(mul_64, r, __REG) { return __MODRM(reg_onebyte64) (__CONTEXT, 0xf7, 4, __reg64(a)); }
	__DEF_INSTR_1(mul_64, m, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0xf7, 4, __MEMOP(a), 0); }
	__DEF_INSTR_1(idiv_64, r, __REG) { return __MODRM(reg_onebyte64) (__CONTEXT, 0xf7, 7, __reg64(a)); }
	__DEF_INSTR_1(idiv_64, m, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0xf7, 7, __MEMOP(a), 0); }
	__DEF_INSTR_1(div_64, r, __REG) { return __MODRM(reg_onebyte64) (__CONTEXT, 0xf7, 6, __reg64(a)); }
	__DEF_INSTR_1(div_64, m, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0xf7, 6, __MEMOP(a), 0); }
#endif


	// Not/neg instructions
	__DEF_INSTR_1(not_8, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf6, 2, __reg8(a)); }
	__DEF_INSTR_1(not_8, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf6, 2, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_not_8, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0xf6, 2, __MEMOP(a), 0)); }
	__DEF_INSTR_1(not_16, r, __REG) { return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0xf7, 2, __reg16(a)); }
	__DEF_INSTR_1(not_16, m, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xf7, 2, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_not_16, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte_opsz) (__CONTEXT_OFFSET(1), 0xf7, 2, __MEMOP(a), 0)); }
	__DEF_INSTR_1(not_32, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf7, 2, __reg32(a)); }
	__DEF_INSTR_1(not_32, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf7, 2, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_not_32, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0xf7, 2, __MEMOP(a), 0)); }
	__DEF_INSTR_1(neg_8, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf6, 3, __reg8(a)); }
	__DEF_INSTR_1(neg_8, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf6, 3, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_neg_8, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0xf6, 3, __MEMOP(a), 0)); }
	__DEF_INSTR_1(neg_16, r, __REG) { return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0xf7, 3, __reg16(a)); }
	__DEF_INSTR_1(neg_16, m, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xf7, 3, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_neg_16, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte_opsz) (__CONTEXT_OFFSET(1), 0xf7, 3, __MEMOP(a), 0)); }
	__DEF_INSTR_1(neg_32, r, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0xf7, 3, __reg32(a)); }
	__DEF_INSTR_1(neg_32, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xf7, 3, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_neg_32, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0xf7, 3, __MEMOP(a), 0)); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_1(not_64, r, __REG) { return __MODRM(reg_onebyte64) (__CONTEXT, 0xf7, 2, __reg64(a)); }
	__DEF_INSTR_1(not_64, m, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0xf7, 2, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_not_64, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte64) (__CONTEXT_OFFSET(1), 0xf7, 2, __MEMOP(a), 0)); }
	__DEF_INSTR_1(neg_64, r, __REG) { return __MODRM(reg_onebyte64) (__CONTEXT, 0xf7, 3, __reg64(a)); }
	__DEF_INSTR_1(neg_64, m, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0xf7, 3, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_neg_64, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte64) (__CONTEXT_OFFSET(1), 0xf7, 3, __MEMOP(a), 0)); }
#endif


	// String instructions
#define __REP_INSTR(n, op) __DEF_INSTR_0(rep_ ## n) { __WRITE_BUF_8(0, 0xf3); return __onebyte(__CONTEXT_OFFSET(1), op) + 1; }
#define __REPE_INSTR(n, op) __DEF_INSTR_0(repe_ ## n) { __WRITE_BUF_8(0, 0xf3); return __onebyte(__CONTEXT_OFFSET(1), op) + 1; }
#define __REPNE_INSTR(n, op) __DEF_INSTR_0(repne_ ## n) { __WRITE_BUF_8(0, 0xf2); return __onebyte(__CONTEXT_OFFSET(1), op) + 1; }
#define __REP_OPSZ_INSTR(n, op) __DEF_INSTR_0(rep_ ## n) { __WRITE_BUF_8(0, 0xf3); return __onebyte_opsz(__CONTEXT_OFFSET(1), op) + 1; }
#define __REPE_OPSZ_INSTR(n, op) __DEF_INSTR_0(repe_ ## n) { __WRITE_BUF_8(0, 0xf3); return __onebyte_opsz(__CONTEXT_OFFSET(1), op) + 1; }
#define __REPNE_OPSZ_INSTR(n, op) __DEF_INSTR_0(repne_ ## n) { __WRITE_BUF_8(0, 0xf2); return __onebyte_opsz(__CONTEXT_OFFSET(1), op) + 1; }

#define __STRING_INSTR(n, op) \
	__ONEBYTE_INSTR(n ## _8, op) \
	__ONEBYTE_OPSZ_INSTR(n ## _16, op + 1) \
	__ONEBYTE_INSTR(n ## _32, op + 1) \
	__REP_INSTR(n ## _8, op) \
	__REP_OPSZ_INSTR(n ## _16, op + 1) \
	__REP_INSTR(n ## _32, op + 1)

#define __STRING_INSTR_FLAGS(n, op) \
	__ONEBYTE_INSTR(n ## _8, op) \
	__ONEBYTE_OPSZ_INSTR(n ## _16, op + 1) \
	__ONEBYTE_INSTR(n ## _32, op + 1) \
	__REPE_INSTR(n ## _8, op) \
	__REPE_OPSZ_INSTR(n ## _16, op + 1) \
	__REPE_INSTR(n ## _32, op + 1) \
	__REPNE_INSTR(n ## _8, op) \
	__REPNE_OPSZ_INSTR(n ## _16, op + 1) \
	__REPNE_INSTR(n ## _32, op + 1)

	__STRING_INSTR(ins, 0x6c)
	__STRING_INSTR(outs, 0x6e)
	__STRING_INSTR(mov, 0xa4)
	__STRING_INSTR_FLAGS(cmps, 0xa6)
	__STRING_INSTR(stos, 0xaa)
	__STRING_INSTR(lods, 0xac)
	__STRING_INSTR_FLAGS(scas, 0xae)

#ifdef __CODEGENX86_64BIT

#define __REP_INSTR_64(n, op) __DEF_INSTR_0(rep_ ## n) { __WRITE_BUF_8(0, 0xf3); return __onebyte64(__CONTEXT_OFFSET(1), op) + 1; }
#define __REPE_INSTR_64(n, op) __DEF_INSTR_0(repe_ ## n) { __WRITE_BUF_8(0, 0xf3); return __onebyte64(__CONTEXT_OFFSET(1), op) + 1; }
#define __REPNE_INSTR_64(n, op) __DEF_INSTR_0(repne_ ## n) { __WRITE_BUF_8(0, 0xf2); return __onebyte64(__CONTEXT_OFFSET(1), op) + 1; }

#define __STRING_INSTR_64(n, op) \
	__ONEBYTE_INSTR_64(n ## _64, op + 1) \
	__REP_INSTR_64(n ## _64, op + 1)

#define __STRING_INSTR_64_FLAGS(n, op) \
	__ONEBYTE_INSTR_64(n ## _64, op + 1) \
	__REPE_INSTR_64(n ## _64, op + 1) \
	__REPNE_INSTR_64(n ## _64, op + 1)

	__STRING_INSTR_64(ins, 0x6c)
	__STRING_INSTR_64(outs, 0x6e)
	__STRING_INSTR_64(mov, 0xa4)
	__STRING_INSTR_64_FLAGS(cmps, 0xa6)
	__STRING_INSTR_64(stos, 0xaa)
	__STRING_INSTR_64(lods, 0xac)
	__STRING_INSTR_64_FLAGS(scas, 0xae)

#endif


	// Return instructions
	__ONEBYTE_INSTR(retn, 0xc3)
	__DEF_INSTR_1(retn, i, __IMM16) { return __onebyte_imm16(__CONTEXT, 0xc2, a); }
	__ONEBYTE_INSTR(retf, 0xcb)
	__DEF_INSTR_1(retf, i, __IMM16) { return __onebyte_imm16(__CONTEXT, 0xca, a); }
	__ONEBYTE_INSTR(iret, 0xcf)


	// Test instruction
	__DEF_INSTR_2(test_8, ri, __REG, __IMM8)
	{
		if (a == REG_AL)
			return __onebyte_imm8(__CONTEXT, 0xa8, b);
		return __MODRM(reg_onebyte_imm8) (__CONTEXT, 0xf6, 0, __reg8(a), b);
	}

	__DEF_INSTR_2(test_16, ri, __REG, __IMM16)
	{
		if (a == REG_AX)
			return __onebyte_opsz_imm16(__CONTEXT, 0xa9, b);
		return __MODRM(reg_onebyte_opsz_imm16) (__CONTEXT, 0xf7, 0, __reg16(a), b);
	}

	__DEF_INSTR_2(test_32, ri, __REG, __IMM32)
	{
		if (a == REG_EAX)
			return __onebyte_imm32(__CONTEXT, 0xa9, b);
		return __MODRM(reg_onebyte_imm32) (__CONTEXT, 0xf7, 0, __reg32(a), b);
	}

#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2(test_64, ri, __REG, __IMM32)
	{
		if (a == REG_RAX)
			return __onebyte64_imm32(__CONTEXT, 0xa9, b);
		return __MODRM(reg_onebyte64_imm32) (__CONTEXT, 0xf7, 0, __reg64(a), b);
	}
#endif

	__DEF_INSTR_2(test_8, mi, __MEM, __IMM8) { return __MODRM(mem_onebyte_imm8) (__CONTEXT, 0xf6, 0, __MEMOP(a), b); }
	__DEF_INSTR_2(test_8, rr, __REG, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0x84, __reg8(b), __reg8(a)); }
	__DEF_INSTR_2(test_8, mr, __MEM, __REG) { return __MODRM(mem_onebyte) (__CONTEXT, 0x84, __reg8(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(test_8, rm, __REG, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0x84, __reg8(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(test_16, mi, __MEM, __IMM16) { return __MODRM(mem_onebyte_opsz_imm16) (__CONTEXT, 0xf7, 0, __MEMOP(a), b); }
	__DEF_INSTR_2(test_16, rr, __REG, __REG) { return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0x85, __reg16(b), __reg16(a)); }
	__DEF_INSTR_2(test_16, mr, __MEM, __REG) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0x85, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(test_16, rm, __REG, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0x85, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(test_32, mi, __MEM, __IMM32) { return __MODRM(mem_onebyte_imm32) (__CONTEXT, 0xf7, 0, __MEMOP(a), b); }
	__DEF_INSTR_2(test_32, rr, __REG, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0x85, __reg32(b), __reg32(a)); }
	__DEF_INSTR_2(test_32, mr, __MEM, __REG) { return __MODRM(mem_onebyte) (__CONTEXT, 0x85, __reg32(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(test_32, rm, __REG, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0x85, __reg32(a), __MEMOP(b), 0); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2(test_64, mi, __MEM, __IMM32) { return __MODRM(mem_onebyte64_imm32) (__CONTEXT, 0xf7, 0, __MEMOP(a), b); }
	__DEF_INSTR_2(test_64, rr, __REG, __REG) { return __MODRM(reg_onebyte64) (__CONTEXT, 0x85, __reg64(b), __reg64(a)); }
	__DEF_INSTR_2(test_64, mr, __MEM, __REG) { return __MODRM(mem_onebyte64) (__CONTEXT, 0x85, __reg64(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(test_64, rm, __REG, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0x85, __reg64(a), __MEMOP(b), 0); }
#endif


	// Exchange instruction
	__DEF_INSTR_2(xchg_16, rr, __REG, __REG)
	{
		if (a == REG_AX)
			return __onebyte_opreg_opsz(__CONTEXT, 0x90, __reg16(b));
		if (b == REG_AX)
			return __onebyte_opreg_opsz(__CONTEXT, 0x90, __reg16(a));
		return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0x87, __reg16(a), __reg16(b));
	}

	__DEF_INSTR_2(xchg_32, rr, __REG, __REG)
	{
#ifdef __CODEGENX86_64BIT
		if ((a == REG_EAX) && (b == REG_EAX))
		{
			// xchg eax, eax should clear top 32-bits, but there is a nop alias there.  Use REX prefix
			// with no bits set to get correct behavior
			__WRITE_BUF_8_8(0, 0x40, 0x90);
			return 2;
		}
#endif
		if (a == REG_EAX)
			return __onebyte_opreg(__CONTEXT, 0x90, __reg32(b));
		if (b == REG_EAX)
			return __onebyte_opreg(__CONTEXT, 0x90, __reg32(a));
		return __MODRM(reg_onebyte) (__CONTEXT, 0x87, __reg32(a), __reg32(b));
	}

#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2(xchg_64, rr, __REG, __REG)
	{
		if (a == REG_RAX)
			return __onebyte64_opreg(__CONTEXT, 0x90, __reg64(b));
		if (b == REG_RAX)
			return __onebyte64_opreg(__CONTEXT, 0x90, __reg64(a));
		return __MODRM(reg_onebyte64) (__CONTEXT, 0x87, __reg64(a), __reg64(b));
	}
#endif

	__DEF_INSTR_2(xchg_8, rr, __REG, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0x86, __reg8(a), __reg8(b)); }
	__DEF_INSTR_2(xchg_8, rm, __REG, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0x86, __reg8(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(xchg_8, mr, __MEM, __REG) { return __MODRM(mem_onebyte) (__CONTEXT, 0x86, __reg8(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_xchg_8, rm, __REG, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0x86, __reg8(a), __MEMOP(b), 0)); }
	__DEF_INSTR_2(lock_xchg_8, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0x86, __reg8(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(xchg_16, rm, __REG, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0x87, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(xchg_16, mr, __MEM, __REG) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0x87, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_xchg_16, rm, __REG, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte_opsz) (__CONTEXT_OFFSET(1), 0x87, __reg16(a), __MEMOP(b), 0)); }
	__DEF_INSTR_2(lock_xchg_16, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_onebyte_opsz) (__CONTEXT_OFFSET(1), 0x87, __reg16(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(xchg_32, rm, __REG, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0x87, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(xchg_32, mr, __MEM, __REG) { return __MODRM(mem_onebyte) (__CONTEXT, 0x87, __reg32(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_xchg_32, rm, __REG, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0x87, __reg32(a), __MEMOP(b), 0)); }
	__DEF_INSTR_2(lock_xchg_32, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_onebyte) (__CONTEXT_OFFSET(1), 0x87, __reg32(b), __MEMOP(a), 0)); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2(xchg_64, rm, __REG, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0x87, __reg64(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(xchg_64, mr, __MEM, __REG) { return __MODRM(mem_onebyte64) (__CONTEXT, 0x87, __reg64(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_xchg_64, rm, __REG, __MEM) { return __LOCKPREFIX(__MODRM(mem_onebyte64) (__CONTEXT_OFFSET(1), 0x87, __reg64(a), __MEMOP(b), 0)); }
	__DEF_INSTR_2(lock_xchg_64, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_onebyte64) (__CONTEXT_OFFSET(1), 0x87, __reg64(b), __MEMOP(a), 0)); }
#endif


	// Compare and exchange instructions
	__DEF_INSTR_2(cmpxchg_8, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xb0, __reg8(b), __reg8(a)); }
	__DEF_INSTR_2(cmpxchg_8, mr, __MEM, __REG) { return __MODRM(mem_twobyte) (__CONTEXT, 0xb0, __reg8(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_cmpxchg_8, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte) (__CONTEXT_OFFSET(1), 0xb0, __reg8(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(cmpxchg_16, rr, __REG, __REG) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xb1, __reg16(b), __reg16(a)); }
	__DEF_INSTR_2(cmpxchg_16, mr, __MEM, __REG) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xb1, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_cmpxchg_16, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte_opsz) (__CONTEXT_OFFSET(1), 0xb1, __reg16(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(cmpxchg_32, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xb1, __reg32(b), __reg32(a)); }
	__DEF_INSTR_2(cmpxchg_32, mr, __MEM, __REG) { return __MODRM(mem_twobyte) (__CONTEXT, 0xb1, __reg32(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_cmpxchg_32, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte) (__CONTEXT_OFFSET(1), 0xb1, __reg32(b), __MEMOP(a), 0)); }
	__DEF_INSTR_1(cmpxchg8b, m, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0xc7, 1, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_cmpxchg8b, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_twobyte) (__CONTEXT_OFFSET(1), 0xc7, 1, __MEMOP(a), 0)); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2(cmpxchg_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xb1, __reg64(b), __reg64(a)); }
	__DEF_INSTR_2(cmpxchg_64, mr, __MEM, __REG) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xb1, __reg64(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_cmpxchg_64, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte64) (__CONTEXT_OFFSET(1), 0xb1, __reg64(b), __MEMOP(a), 0)); }
	__DEF_INSTR_1(cmpxchg16b, m, __MEM) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xc7, 1, __MEMOP(a), 0); }
	__DEF_INSTR_1(lock_cmpxchg16b, m, __MEM) { return __LOCKPREFIX(__MODRM(mem_twobyte64) (__CONTEXT_OFFSET(1), 0xc7, 1, __MEMOP(a), 0)); }
#endif


	// Exchange and add instruction
	__DEF_INSTR_2(xadd_8, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xc0, __reg8(b), __reg8(a)); }
	__DEF_INSTR_2(xadd_8, mr, __MEM, __REG) { return __MODRM(mem_twobyte) (__CONTEXT, 0xc0, __reg8(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_xadd_8, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte) (__CONTEXT_OFFSET(1), 0xc0, __reg8(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(xadd_16, rr, __REG, __REG) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xc1, __reg16(b), __reg16(a)); }
	__DEF_INSTR_2(xadd_16, mr, __MEM, __REG) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xc1, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_xadd_16, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte_opsz) (__CONTEXT_OFFSET(1), 0xc1, __reg16(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(xadd_32, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xc1, __reg32(b), __reg32(a)); }
	__DEF_INSTR_2(xadd_32, mr, __MEM, __REG) { return __MODRM(mem_twobyte) (__CONTEXT, 0xc1, __reg32(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_xadd_32, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte) (__CONTEXT_OFFSET(1), 0xc1, __reg32(b), __MEMOP(a), 0)); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2(xadd_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xc1, __reg64(b), __reg64(a)); }
	__DEF_INSTR_2(xadd_64, mr, __MEM, __REG) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xc1, __reg64(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(lock_xadd_64, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte64) (__CONTEXT_OFFSET(1), 0xc1, __reg64(b), __MEMOP(a), 0)); }
#endif


	// Move instructions
#ifdef __CODEGENX86_32BIT
	__DEF_INSTR_2(mov_8, rm, __REG, __MEM)
	{
		if ((a == REG_AL) && (__MEM_BASE(b) == NONE) && (__MEM_INDEX(b) == NONE))
			return __onebyte_imm32(__CONTEXT, 0xa0, (int32_t)__MEM_OFFSET(b));
		return __MODRM(mem_onebyte) (__CONTEXT, 0x8a, __reg8(a), __MEMOP(b), 0);
	}

	__DEF_INSTR_2(mov_8, mr, __MEM, __REG)
	{
		if ((b == REG_AL) && (__MEM_BASE(a) == NONE) && (__MEM_INDEX(a) == NONE))
			return __onebyte_imm32(__CONTEXT, 0xa2, (int32_t)__MEM_OFFSET(a));
		return __MODRM(mem_onebyte) (__CONTEXT, 0x88, __reg8(b), __MEMOP(a), 0);
	}

	__DEF_INSTR_2(mov_16, rm, __REG, __MEM)
	{
		if ((a == REG_AX) && (__MEM_BASE(b) == NONE) && (__MEM_INDEX(b) == NONE))
			return __onebyte_opsz_imm32(__CONTEXT, 0xa1, (int32_t)__MEM_OFFSET(b));
		return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0x8b, __reg16(a), __MEMOP(b), 0);
	}

	__DEF_INSTR_2(mov_16, mr, __MEM, __REG)
	{
		if ((b == REG_AX) && (__MEM_BASE(a) == NONE) && (__MEM_INDEX(a) == NONE))
			return __onebyte_opsz_imm32(__CONTEXT, 0xa3, (int32_t)__MEM_OFFSET(a));
		return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0x89, __reg16(b), __MEMOP(a), 0);
	}

	__DEF_INSTR_2(mov_32, rm, __REG, __MEM)
	{
		if ((a == REG_EAX) && (__MEM_BASE(b) == NONE) && (__MEM_INDEX(b) == NONE))
			return __onebyte_imm32(__CONTEXT, 0xa1, (int32_t)__MEM_OFFSET(b));
		return __MODRM(mem_onebyte) (__CONTEXT, 0x8b, __reg32(a), __MEMOP(b), 0);
	}

	__DEF_INSTR_2(mov_32, mr, __MEM, __REG)
	{
		if ((b == REG_EAX) && (__MEM_BASE(a) == NONE) && (__MEM_INDEX(a) == NONE))
			return __onebyte_imm32(__CONTEXT, 0xa3, (int32_t)__MEM_OFFSET(a));
		return __MODRM(mem_onebyte) (__CONTEXT, 0x89, __reg32(b), __MEMOP(a), 0);
	}
#endif

	__DEF_INSTR_2(mov_8, rr, __REG, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0x8a, __reg8(a), __reg8(b)); }
	__DEF_INSTR_2(mov_8, ri, __REG, __IMM8) { return __onebyte_opreg_imm8(__CONTEXT, 0xb0, __reg8(a), b); }
	__DEF_INSTR_2(mov_8, mi, __MEM, __IMM8) { return __MODRM(mem_onebyte_imm8) (__CONTEXT, 0xc6, 0, __MEMOP(a), b); }
	__DEF_INSTR_2(mov_16, rr, __REG, __REG) { return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0x8b, __reg16(a), __reg16(b)); }
	__DEF_INSTR_2(mov_16, ri, __REG, __IMM16) { return __onebyte_opreg_opsz_imm16(__CONTEXT, 0xb8, __reg16(a), b); }
	__DEF_INSTR_2(mov_16, mi, __MEM, __IMM16) { return __MODRM(mem_onebyte_opsz_imm16) (__CONTEXT, 0xc7, 0, __MEMOP(a), b); }
	__DEF_INSTR_2(mov_32, rr, __REG, __REG) { return __MODRM(reg_onebyte) (__CONTEXT, 0x8b, __reg32(a), __reg32(b)); }
	__DEF_INSTR_2(mov_32, ri, __REG, __IMM32) { return __onebyte_opreg_imm32(__CONTEXT, 0xb8, __reg32(a), b); }
	__DEF_INSTR_2(mov_32, mi, __MEM, __IMM32) { return __MODRM(mem_onebyte_imm32) (__CONTEXT, 0xc7, 0, __MEMOP(a), b); }

#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2(mov_8, rm, __REG, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0x8a, __reg8(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(mov_8, mr, __MEM, __REG) { return __MODRM(mem_onebyte) (__CONTEXT, 0x88, __reg8(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(mov_16, rm, __REG, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0x8b, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(mov_16, mr, __MEM, __REG) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0x89, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(mov_32, rm, __REG, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0x8b, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(mov_32, mr, __MEM, __REG) { return __MODRM(mem_onebyte) (__CONTEXT, 0x89, __reg32(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(mov_64, rm, __REG, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0x8b, __reg64(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(mov_64, mr, __MEM, __REG) { return __MODRM(mem_onebyte64) (__CONTEXT, 0x89, __reg64(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(mov_64, rr, __REG, __REG) { return __MODRM(reg_onebyte64) (__CONTEXT, 0x8b, __reg64(a), __reg64(b)); }
	__DEF_INSTR_2(mov_64, ri, __REG, __IMM64) { return __onebyte64_opreg_imm64(__CONTEXT, 0xb8, __reg64(a), b); }
	__DEF_INSTR_2(mov_64, mi, __MEM, __IMM32) { return __MODRM(mem_onebyte64_imm32) (__CONTEXT, 0xc7, 0, __MEMOP(a), b); }
#endif


	// Move sign/zero extend instructions
	__DEF_INSTR_2(movzx_16_8, rr, __REG, __REG) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xb6, __reg16(a), __reg8(b)); }
	__DEF_INSTR_2(movzx_16_8, rm, __REG, __MEM) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xb6, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(movzx_32_8, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xb6, __reg32(a), __reg8(b)); }
	__DEF_INSTR_2(movzx_32_8, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0xb6, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(movzx_32_16, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xb7, __reg32(a), __reg16(b)); }
	__DEF_INSTR_2(movzx_32_16, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0xb7, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(movsx_16_8, rr, __REG, __REG) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xbe, __reg16(a), __reg8(b)); }
	__DEF_INSTR_2(movsx_16_8, rm, __REG, __MEM) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xbe, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(movsx_32_8, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xbe, __reg32(a), __reg8(b)); }
	__DEF_INSTR_2(movsx_32_8, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0xbe, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(movsx_32_16, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xbf, __reg32(a), __reg16(b)); }
	__DEF_INSTR_2(movsx_32_16, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0xbf, __reg32(a), __MEMOP(b), 0); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2(movzx_64_8, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xb6, __reg64(a), __reg8(b)); }
	__DEF_INSTR_2(movzx_64_8, rm, __REG, __MEM) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xb6, __reg64(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(movzx_64_16, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xb7, __reg64(a), __reg16(b)); }
	__DEF_INSTR_2(movzx_64_16, rm, __REG, __MEM) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xb7, __reg64(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(movsx_64_8, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xbe, __reg64(a), __reg8(b)); }
	__DEF_INSTR_2(movsx_64_8, rm, __REG, __MEM) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xbe, __reg64(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(movsx_64_16, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xbf, __reg64(a), __reg16(b)); }
	__DEF_INSTR_2(movsx_64_16, rm, __REG, __MEM) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xbf, __reg64(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(movsxd_64_32, rr, __REG, __REG) { return __MODRM(reg_onebyte64) (__CONTEXT, 0x63, __reg64(a), __reg32(b)); }
	__DEF_INSTR_2(movsxd_64_32, rm, __REG, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0x63, __reg64(a), __MEMOP(b), 0); }
#endif


	// Bit test instructions
	__DEF_INSTR_2(bt_16, rr, __REG, __REG) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xa3, __reg16(b), __reg16(a)); }
	__DEF_INSTR_2(bt_16, mr, __MEM, __REG) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xa3, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(bt_16, ri, __REG, __IMM8) { return __MODRM(reg_twobyte_opsz_imm8) (__CONTEXT, 0xba, 4, __reg16(a), b); }
	__DEF_INSTR_2(bt_16, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte_opsz_imm8) (__CONTEXT, 0xba, 4, __MEMOP(a), b); }
	__DEF_INSTR_2(bt_32, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xa3, __reg32(b), __reg32(a)); }
	__DEF_INSTR_2(bt_32, mr, __MEM, __REG) { return __MODRM(mem_twobyte) (__CONTEXT, 0xa3, __reg32(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(bt_32, ri, __REG, __IMM8) { return __MODRM(reg_twobyte_imm8) (__CONTEXT, 0xba, 4, __reg32(a), b); }
	__DEF_INSTR_2(bt_32, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte_imm8) (__CONTEXT, 0xba, 4, __MEMOP(a), b); }
	__DEF_INSTR_2(bts_16, rr, __REG, __REG) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xab, __reg16(b), __reg16(a)); }
	__DEF_INSTR_2(bts_16, mr, __MEM, __REG) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xab, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(bts_16, ri, __REG, __IMM8) { return __MODRM(reg_twobyte_opsz_imm8) (__CONTEXT, 0xba, 5, __reg16(a), b); }
	__DEF_INSTR_2(bts_16, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte_opsz_imm8) (__CONTEXT, 0xba, 5, __MEMOP(a), b); }
	__DEF_INSTR_2(lock_bts_16, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte_opsz) (__CONTEXT_OFFSET(1), 0xab, __reg16(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(lock_bts_16, mi, __MEM, __IMM8) { return __LOCKPREFIX(__MODRM(mem_twobyte_opsz_imm8) (__CONTEXT_OFFSET(1), 0xba, 5, __MEMOP(a), b)); }
	__DEF_INSTR_2(bts_32, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xab, __reg32(b), __reg32(a)); }
	__DEF_INSTR_2(bts_32, mr, __MEM, __REG) { return __MODRM(mem_twobyte) (__CONTEXT, 0xab, __reg32(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(bts_32, ri, __REG, __IMM8) { return __MODRM(reg_twobyte_imm8) (__CONTEXT, 0xba, 5, __reg32(a), b); }
	__DEF_INSTR_2(bts_32, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte_imm8) (__CONTEXT, 0xba, 5, __MEMOP(a), b); }
	__DEF_INSTR_2(lock_bts_32, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte) (__CONTEXT_OFFSET(1), 0xab, __reg32(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(lock_bts_32, mi, __MEM, __IMM8) { return __LOCKPREFIX(__MODRM(mem_twobyte_imm8) (__CONTEXT_OFFSET(1), 0xba, 5, __MEMOP(a), b)); }
	__DEF_INSTR_2(btr_16, rr, __REG, __REG) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xb3, __reg16(b), __reg16(a)); }
	__DEF_INSTR_2(btr_16, mr, __MEM, __REG) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xb3, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(btr_16, ri, __REG, __IMM8) { return __MODRM(reg_twobyte_opsz_imm8) (__CONTEXT, 0xba, 6, __reg16(a), b); }
	__DEF_INSTR_2(btr_16, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte_opsz_imm8) (__CONTEXT, 0xba, 6, __MEMOP(a), b); }
	__DEF_INSTR_2(lock_btr_16, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte_opsz) (__CONTEXT_OFFSET(1), 0xb3, __reg16(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(lock_btr_16, mi, __MEM, __IMM8) { return __LOCKPREFIX(__MODRM(mem_twobyte_opsz_imm8) (__CONTEXT_OFFSET(1), 0xba, 6, __MEMOP(a), b)); }
	__DEF_INSTR_2(btr_32, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xb3, __reg32(b), __reg32(a)); }
	__DEF_INSTR_2(btr_32, mr, __MEM, __REG) { return __MODRM(mem_twobyte) (__CONTEXT, 0xb3, __reg32(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(btr_32, ri, __REG, __IMM8) { return __MODRM(reg_twobyte_imm8) (__CONTEXT, 0xba, 6, __reg32(a), b); }
	__DEF_INSTR_2(btr_32, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte_imm8) (__CONTEXT, 0xba, 6, __MEMOP(a), b); }
	__DEF_INSTR_2(lock_btr_32, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte) (__CONTEXT_OFFSET(1), 0xb3, __reg32(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(lock_btr_32, mi, __MEM, __IMM8) { return __LOCKPREFIX(__MODRM(mem_twobyte_imm8) (__CONTEXT_OFFSET(1), 0xba, 6, __MEMOP(a), b)); }
	__DEF_INSTR_2(btc_16, rr, __REG, __REG) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xbb, __reg16(b), __reg16(a)); }
	__DEF_INSTR_2(btc_16, mr, __MEM, __REG) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xbb, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(btc_16, ri, __REG, __IMM8) { return __MODRM(reg_twobyte_opsz_imm8) (__CONTEXT, 0xba, 7, __reg16(a), b); }
	__DEF_INSTR_2(btc_16, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte_opsz_imm8) (__CONTEXT, 0xba, 7, __MEMOP(a), b); }
	__DEF_INSTR_2(lock_btc_16, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte_opsz) (__CONTEXT_OFFSET(1), 0xbb, __reg16(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(lock_btc_16, mi, __MEM, __IMM8) { return __LOCKPREFIX(__MODRM(mem_twobyte_opsz_imm8) (__CONTEXT_OFFSET(1), 0xba, 7, __MEMOP(a), b)); }
	__DEF_INSTR_2(btc_32, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xbb, __reg32(b), __reg32(a)); }
	__DEF_INSTR_2(btc_32, mr, __MEM, __REG) { return __MODRM(mem_twobyte) (__CONTEXT, 0xbb, __reg32(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(btc_32, ri, __REG, __IMM8) { return __MODRM(reg_twobyte_imm8) (__CONTEXT, 0xba, 7, __reg32(a), b); }
	__DEF_INSTR_2(btc_32, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte_imm8) (__CONTEXT, 0xba, 7, __MEMOP(a), b); }
	__DEF_INSTR_2(lock_btc_32, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte) (__CONTEXT_OFFSET(1), 0xbb, __reg32(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(lock_btc_32, mi, __MEM, __IMM8) { return __LOCKPREFIX(__MODRM(mem_twobyte_imm8) (__CONTEXT_OFFSET(1), 0xba, 7, __MEMOP(a), b)); }
	__DEF_INSTR_2(bsf_16, rr, __REG, __REG) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xbc, __reg16(a), __reg16(b)); }
	__DEF_INSTR_2(bsf_16, rm, __REG, __MEM) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xbc, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(bsf_32, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xbc, __reg32(a), __reg32(b)); }
	__DEF_INSTR_2(bsf_32, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0xbc, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(bsr_16, rr, __REG, __REG) { return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xbd, __reg16(a), __reg16(b)); }
	__DEF_INSTR_2(bsr_16, rm, __REG, __MEM) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xbd, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(bsr_32, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0xbd, __reg32(a), __reg32(b)); }
	__DEF_INSTR_2(bsr_32, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0xbd, __reg32(a), __MEMOP(b), 0); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2(bt_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xa3, __reg64(b), __reg64(a)); }
	__DEF_INSTR_2(bt_64, mr, __MEM, __REG) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xa3, __reg64(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(bt_64, ri, __REG, __IMM8) { return __MODRM(reg_twobyte64_imm8) (__CONTEXT, 0xba, 4, __reg64(a), b); }
	__DEF_INSTR_2(bt_64, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte64_imm8) (__CONTEXT, 0xba, 4, __MEMOP(a), b); }
	__DEF_INSTR_2(bts_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xab, __reg64(b), __reg64(a)); }
	__DEF_INSTR_2(bts_64, mr, __MEM, __REG) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xab, __reg64(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(bts_64, ri, __REG, __IMM8) { return __MODRM(reg_twobyte64_imm8) (__CONTEXT, 0xba, 5, __reg64(a), b); }
	__DEF_INSTR_2(bts_64, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte64_imm8) (__CONTEXT, 0xba, 5, __MEMOP(a), b); }
	__DEF_INSTR_2(lock_bts_64, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte64) (__CONTEXT_OFFSET(1), 0xab, __reg64(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(lock_bts_64, mi, __MEM, __IMM8) { return __LOCKPREFIX(__MODRM(mem_twobyte64_imm8) (__CONTEXT_OFFSET(1), 0xba, 5, __MEMOP(a), b)); }
	__DEF_INSTR_2(btr_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xb3, __reg64(b), __reg64(a)); }
	__DEF_INSTR_2(btr_64, mr, __MEM, __REG) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xb3, __reg64(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(btr_64, ri, __REG, __IMM8) { return __MODRM(reg_twobyte64_imm8) (__CONTEXT, 0xba, 6, __reg64(a), b); }
	__DEF_INSTR_2(btr_64, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte64_imm8) (__CONTEXT, 0xba, 6, __MEMOP(a), b); }
	__DEF_INSTR_2(lock_btr_64, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte64) (__CONTEXT_OFFSET(1), 0xb3, __reg64(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(lock_btr_64, mi, __MEM, __IMM8) { return __LOCKPREFIX(__MODRM(mem_twobyte64_imm8) (__CONTEXT_OFFSET(1), 0xba, 6, __MEMOP(a), b)); }
	__DEF_INSTR_2(btc_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xbb, __reg64(b), __reg64(a)); }
	__DEF_INSTR_2(btc_64, mr, __MEM, __REG) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xbb, __reg64(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(btc_64, ri, __REG, __IMM8) { return __MODRM(reg_twobyte64_imm8) (__CONTEXT, 0xba, 7, __reg64(a), b); }
	__DEF_INSTR_2(btc_64, mi, __MEM, __IMM8) { return __MODRM(mem_twobyte64_imm8) (__CONTEXT, 0xba, 7, __MEMOP(a), b); }
	__DEF_INSTR_2(lock_btc_64, mr, __MEM, __REG) { return __LOCKPREFIX(__MODRM(mem_twobyte64) (__CONTEXT_OFFSET(1), 0xbb, __reg64(b), __MEMOP(a), 0)); }
	__DEF_INSTR_2(lock_btc_64, mi, __MEM, __IMM8) { return __LOCKPREFIX(__MODRM(mem_twobyte64_imm8) (__CONTEXT_OFFSET(1), 0xba, 7, __MEMOP(a), b)); }
	__DEF_INSTR_2(bsf_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xbc, __reg64(a), __reg64(b)); }
	__DEF_INSTR_2(bsf_64, rm, __REG, __MEM) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xbc, __reg64(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(bsr_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64) (__CONTEXT, 0xbd, __reg64(a), __reg64(b)); }
	__DEF_INSTR_2(bsr_64, rm, __REG, __MEM) { return __MODRM(mem_twobyte64) (__CONTEXT, 0xbd, __reg64(a), __MEMOP(b), 0); }
#endif


	// Load effective address instruction
	__DEF_INSTR_2(lea_16, rm, __REG, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0x8d, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(lea_32, rm, __REG, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0x8d, __reg32(a), __MEMOP(b), 0); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2(lea_64, rm, __REG, __MEM) { return __MODRM(mem_onebyte64) (__CONTEXT, 0x8d, __reg64(a), __MEMOP(b), 0); }
#endif


	// Load segment and offset instructions
#ifdef __CODEGENX86_32BIT
	__DEF_INSTR_2(les_16, rm, __REG, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xc4, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(les_32, rm, __REG, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xc4, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(lds_16, rm, __REG, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xc5, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(lds_32, rm, __REG, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xc5, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(lss_16, rm, __REG, __MEM) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xb2, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(lss_32, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0xb2, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(lfs_16, rm, __REG, __MEM) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xb4, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(lfs_32, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0xb4, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(lgs_16, rm, __REG, __MEM) { return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xb5, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(lgs_32, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0xb5, __reg32(a), __MEMOP(b), 0); }
#endif


	// Shift/rotate instructions
	__DEF_INSTR_2_ARG(shiftrot_8, ri, __REG, __IMM8, uint8_t op)
	{
		if (b == 1)
			return __MODRM(reg_onebyte) (__CONTEXT, 0xd0, op, __reg8(a));
		return __MODRM(reg_onebyte_imm8) (__CONTEXT, 0xc0, op, __reg8(a), b);
	}

	__DEF_INSTR_2_ARG(shiftrot_8, mi, __MEM, __IMM8, uint8_t op)
	{
		if (b == 1)
			return __MODRM(mem_onebyte) (__CONTEXT, 0xd0, op, __MEMOP(a), 0);
		return __MODRM(mem_onebyte_imm8) (__CONTEXT, 0xc0, op, __MEMOP(a), b);
	}

	__DEF_INSTR_2_ARG(shiftrot_16, ri, __REG, __IMM8, uint8_t op)
	{
		if (b == 1)
			return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0xd1, op, __reg16(a));
		return __MODRM(reg_onebyte_opsz_imm8) (__CONTEXT, 0xc1, op, __reg16(a), b);
	}

	__DEF_INSTR_2_ARG(shiftrot_16, mi, __MEM, __IMM8, uint8_t op)
	{
		if (b == 1)
			return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xd1, op, __MEMOP(a), 0);
		return __MODRM(mem_onebyte_opsz_imm8) (__CONTEXT, 0xc1, op, __MEMOP(a), b);
	}

	__DEF_INSTR_2_ARG(shiftrot_32, ri, __REG, __IMM8, uint8_t op)
	{
		if (b == 1)
			return __MODRM(reg_onebyte) (__CONTEXT, 0xd1, op, __reg32(a));
		return __MODRM(reg_onebyte_imm8) (__CONTEXT, 0xc1, op, __reg32(a), b);
	}

	__DEF_INSTR_2_ARG(shiftrot_32, mi, __MEM, __IMM8, uint8_t op)
	{
		if (b == 1)
			return __MODRM(mem_onebyte) (__CONTEXT, 0xd1, op, __MEMOP(a), 0);
		return __MODRM(mem_onebyte_imm8) (__CONTEXT, 0xc1, op, __MEMOP(a), b);
	}

#define __ASSERT_SHIFT_BY_CL (void)b; __CGX86_ASSERT(b == REG_CL, "Shift/rotate count must be immediate or CL");
	__DEF_INSTR_2_ARG(shiftrot_8, rr, __REG, __REG, uint8_t op) { __ASSERT_SHIFT_BY_CL; return __MODRM(reg_onebyte) (__CONTEXT, 0xd2, op, __reg8(a)); }
	__DEF_INSTR_2_ARG(shiftrot_8, mr, __MEM, __REG, uint8_t op) { __ASSERT_SHIFT_BY_CL; return __MODRM(mem_onebyte) (__CONTEXT, 0xd2, op, __MEMOP(a), 0); }
	__DEF_INSTR_2_ARG(shiftrot_16, rr, __REG, __REG, uint8_t op) { __ASSERT_SHIFT_BY_CL; return __MODRM(reg_onebyte_opsz) (__CONTEXT, 0xd3, op, __reg16(a)); }
	__DEF_INSTR_2_ARG(shiftrot_16, mr, __MEM, __REG, uint8_t op) { __ASSERT_SHIFT_BY_CL; return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0xd3, op, __MEMOP(a), 0); }
	__DEF_INSTR_2_ARG(shiftrot_32, rr, __REG, __REG, uint8_t op) { __ASSERT_SHIFT_BY_CL; return __MODRM(reg_onebyte) (__CONTEXT, 0xd3, op, __reg32(a)); }
	__DEF_INSTR_2_ARG(shiftrot_32, mr, __MEM, __REG, uint8_t op) { __ASSERT_SHIFT_BY_CL; return __MODRM(mem_onebyte) (__CONTEXT, 0xd3, op, __MEMOP(a), 0); }

#define __SHIFTROT_INSTR(n, op) \
	__DEF_INSTR_2(n ## _8, rr, __REG, __REG) { return __NAME(shiftrot_8, rr) (__CONTEXT, op, a, b); } \
	__DEF_INSTR_2(n ## _8, mr, __MEM, __REG) { return __NAME(shiftrot_8, mr) (__CONTEXT, op, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _8, ri, __REG, __IMM8) { return __NAME(shiftrot_8, ri) (__CONTEXT, op, a, b); } \
	__DEF_INSTR_2(n ## _8, mi, __MEM, __IMM8) { return __NAME(shiftrot_8, mi) (__CONTEXT, op, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _16, rr, __REG, __REG) { return __NAME(shiftrot_16, rr) (__CONTEXT, op, a, b); } \
	__DEF_INSTR_2(n ## _16, mr, __MEM, __REG) { return __NAME(shiftrot_16, mr) (__CONTEXT, op, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _16, ri, __REG, __IMM8) { return __NAME(shiftrot_16, ri) (__CONTEXT, op, a, b); } \
	__DEF_INSTR_2(n ## _16, mi, __MEM, __IMM8) { return __NAME(shiftrot_16, mi) (__CONTEXT, op, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _32, rr, __REG, __REG) { return __NAME(shiftrot_32, rr) (__CONTEXT, op, a, b); } \
	__DEF_INSTR_2(n ## _32, mr, __MEM, __REG) { return __NAME(shiftrot_32, mr) (__CONTEXT, op, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _32, ri, __REG, __IMM8) { return __NAME(shiftrot_32, ri) (__CONTEXT, op, a, b); } \
	__DEF_INSTR_2(n ## _32, mi, __MEM, __IMM8) { return __NAME(shiftrot_32, mi) (__CONTEXT, op, __MEMOP(a), b); }

	__SHIFTROT_INSTR(rol, 0)
	__SHIFTROT_INSTR(ror, 1)
	__SHIFTROT_INSTR(rcl, 2)
	__SHIFTROT_INSTR(rcr, 3)
	__SHIFTROT_INSTR(shl, 4)
	__SHIFTROT_INSTR(shr, 5)
	__SHIFTROT_INSTR(sar, 7)

#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2_ARG(shiftrot_64, ri, __REG, __IMM8, uint8_t op)
	{
		if (b == 1)
			return __MODRM(reg_onebyte64) (__CONTEXT, 0xd1, op, __reg64(a));
		return __MODRM(reg_onebyte64_imm8) (__CONTEXT, 0xc1, op, __reg64(a), b);
	}

	__DEF_INSTR_2_ARG(shiftrot_64, mi, __MEM, __IMM8, uint8_t op)
	{
		if (b == 1)
			return __MODRM(mem_onebyte64) (__CONTEXT, 0xd1, op, __MEMOP(a), 0);
		return __MODRM(mem_onebyte64_imm8) (__CONTEXT, 0xc1, op, __MEMOP(a), b);
	}

	__DEF_INSTR_2_ARG(shiftrot_64, rr, __REG, __REG, uint8_t op) { __ASSERT_SHIFT_BY_CL; return __MODRM(reg_onebyte64) (__CONTEXT, 0xd3, op, __reg64(a)); }
	__DEF_INSTR_2_ARG(shiftrot_64, mr, __MEM, __REG, uint8_t op) { __ASSERT_SHIFT_BY_CL; return __MODRM(mem_onebyte64) (__CONTEXT, 0xd3, op, __MEMOP(a), 0); }

#define __SHIFTROT_INSTR_64(n, op) \
	__DEF_INSTR_2(n ## _64, rr, __REG, __REG) { return __NAME(shiftrot_64, rr) (__CONTEXT, op, a, b); } \
	__DEF_INSTR_2(n ## _64, mr, __MEM, __REG) { return __NAME(shiftrot_64, mr) (__CONTEXT, op, __MEMOP(a), b); } \
	__DEF_INSTR_2(n ## _64, ri, __REG, __IMM8) { return __NAME(shiftrot_64, ri) (__CONTEXT, op, a, b); } \
	__DEF_INSTR_2(n ## _64, mi, __MEM, __IMM8) { return __NAME(shiftrot_64, mi) (__CONTEXT, op, __MEMOP(a), b); }

	__SHIFTROT_INSTR_64(rol, 0)
	__SHIFTROT_INSTR_64(ror, 1)
	__SHIFTROT_INSTR_64(rcl, 2)
	__SHIFTROT_INSTR_64(rcr, 3)
	__SHIFTROT_INSTR_64(shl, 4)
	__SHIFTROT_INSTR_64(shr, 5)
	__SHIFTROT_INSTR_64(sar, 7)
#endif


	// Shift double instructions
#define __ASSERT_DBLSHIFT_BY_CL (void)c; __CGX86_ASSERT(c == REG_CL, "Shift/rotate count must be immediate or CL");
	__DEF_INSTR_3(shld_16, rri, __REG, __REG, __IMM8) { return __MODRM(reg_twobyte_opsz_imm8) (__CONTEXT, 0xa4, __reg16(b), __reg16(a), c); }
	__DEF_INSTR_3(shld_16, mri, __MEM, __REG, __IMM8) { return __MODRM(mem_twobyte_opsz_imm8) (__CONTEXT, 0xa4, __reg16(b), __MEMOP(a), c); }
	__DEF_INSTR_3(shld_16, rrr, __REG, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xa5, __reg16(b), __reg16(a)); }
	__DEF_INSTR_3(shld_16, mrr, __MEM, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xa5, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_3(shld_32, rri, __REG, __REG, __IMM8) { return __MODRM(reg_twobyte_imm8) (__CONTEXT, 0xa4, __reg32(b), __reg32(a), c); }
	__DEF_INSTR_3(shld_32, mri, __MEM, __REG, __IMM8) { return __MODRM(mem_twobyte_imm8) (__CONTEXT, 0xa4, __reg32(b), __MEMOP(a), c); }
	__DEF_INSTR_3(shld_32, rrr, __REG, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(reg_twobyte) (__CONTEXT, 0xa5, __reg32(b), __reg32(a)); }
	__DEF_INSTR_3(shld_32, mrr, __MEM, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(mem_twobyte) (__CONTEXT, 0xa5, __reg32(b), __MEMOP(a), 0); }
	__DEF_INSTR_3(shrd_16, rri, __REG, __REG, __IMM8) { return __MODRM(reg_twobyte_opsz_imm8) (__CONTEXT, 0xac, __reg16(b), __reg16(a), c); }
	__DEF_INSTR_3(shrd_16, mri, __MEM, __REG, __IMM8) { return __MODRM(mem_twobyte_opsz_imm8) (__CONTEXT, 0xac, __reg16(b), __MEMOP(a), c); }
	__DEF_INSTR_3(shrd_16, rrr, __REG, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(reg_twobyte_opsz) (__CONTEXT, 0xad, __reg16(b), __reg16(a)); }
	__DEF_INSTR_3(shrd_16, mrr, __MEM, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(mem_twobyte_opsz) (__CONTEXT, 0xad, __reg16(b), __MEMOP(a), 0); }
	__DEF_INSTR_3(shrd_32, rri, __REG, __REG, __IMM8) { return __MODRM(reg_twobyte_imm8) (__CONTEXT, 0xac, __reg32(b), __reg32(a), c); }
	__DEF_INSTR_3(shrd_32, mri, __MEM, __REG, __IMM8) { return __MODRM(mem_twobyte_imm8) (__CONTEXT, 0xac, __reg32(b), __MEMOP(a), c); }
	__DEF_INSTR_3(shrd_32, rrr, __REG, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(reg_twobyte) (__CONTEXT, 0xad, __reg32(b), __reg32(a)); }
	__DEF_INSTR_3(shrd_32, mrr, __MEM, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(mem_twobyte) (__CONTEXT, 0xad, __reg32(b), __MEMOP(a), 0); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_3(shld_64, rri, __REG, __REG, __IMM8) { return __MODRM(reg_twobyte64_imm8) (__CONTEXT, 0xa4, __reg64(b), __reg64(a), c); }
	__DEF_INSTR_3(shld_64, mri, __MEM, __REG, __IMM8) { return __MODRM(mem_twobyte64_imm8) (__CONTEXT, 0xa4, __reg64(b), __MEMOP(a), c); }
	__DEF_INSTR_3(shld_64, rrr, __REG, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(reg_twobyte64) (__CONTEXT, 0xa5, __reg64(b), __reg64(a)); }
	__DEF_INSTR_3(shld_64, mrr, __MEM, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(mem_twobyte64) (__CONTEXT, 0xa5, __reg64(b), __MEMOP(a), 0); }
	__DEF_INSTR_3(shrd_64, rri, __REG, __REG, __IMM8) { return __MODRM(reg_twobyte64_imm8) (__CONTEXT, 0xac, __reg64(b), __reg64(a), c); }
	__DEF_INSTR_3(shrd_64, mri, __MEM, __REG, __IMM8) { return __MODRM(mem_twobyte64_imm8) (__CONTEXT, 0xac, __reg64(b), __MEMOP(a), c); }
	__DEF_INSTR_3(shrd_64, rrr, __REG, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(reg_twobyte64) (__CONTEXT, 0xad, __reg64(b), __reg64(a)); }
	__DEF_INSTR_3(shrd_64, mrr, __MEM, __REG, __REG) { __ASSERT_DBLSHIFT_BY_CL; return __MODRM(mem_twobyte64) (__CONTEXT, 0xad, __reg64(b), __MEMOP(a), 0); }
#endif


	// Enter/leave instructions
	__DEF_INSTR_2(enter, ii, __IMM16, __IMM8)
	{
		__TRANSLATE_UNUSED
		__NO_ASSERT
		__WRITE_BUF_8(0, 0xc8);
		__WRITE_BUF_16(1, a);
		__WRITE_BUF_8(3, b);
		return 4;
	}

	__ONEBYTE_INSTR(leave, 0xc9)


	// Interrupt instructions
	__DEF_INSTR_1(int, i, __IMM8) { return __onebyte_imm8(__CONTEXT, 0xcd, a); }
	__ONEBYTE_INSTR(int1, 0xf1)
	__ONEBYTE_INSTR(int3, 0xcc)
	__ONEBYTE_INSTR(into, 0xce)


	// In/out instructions
	__DEF_INSTR_2(in_8, rr, __REG, __REG) { (void)a; (void)b; __CGX86_ASSERT((a == REG_AL) && (b == REG_DX), "Incorrect arguments to IN instruction"); return __onebyte(__CONTEXT, 0xec); }
	__DEF_INSTR_2(in_8, ri, __REG, __IMM8) { (void)a; __CGX86_ASSERT(a == REG_AL, "Incorrect arguments to IN instruction"); return __onebyte_imm8(__CONTEXT, 0xe4, b); }
	__DEF_INSTR_2(in_16, rr, __REG, __REG) { (void)a; (void)b; __CGX86_ASSERT((a == REG_AX) && (b == REG_DX), "Incorrect arguments to IN instruction"); return __onebyte_opsz(__CONTEXT, 0xed); }
	__DEF_INSTR_2(in_16, ri, __REG, __IMM8) { (void)a; __CGX86_ASSERT(a == REG_AX, "Incorrect arguments to IN instruction"); return __onebyte_opsz_imm8(__CONTEXT, 0xe5, b); }
	__DEF_INSTR_2(in_32, rr, __REG, __REG) { (void)a; (void)b; __CGX86_ASSERT((a == REG_EAX) && (b == REG_DX), "Incorrect arguments to IN instruction"); return __onebyte(__CONTEXT, 0xed); }
	__DEF_INSTR_2(in_32, ri, __REG, __IMM8) { (void)a; __CGX86_ASSERT(a == REG_EAX, "Incorrect arguments to IN instruction"); return __onebyte_imm8(__CONTEXT, 0xe5, b); }
	__DEF_INSTR_2(out_8, rr, __REG, __REG) { (void)a; (void)b; __CGX86_ASSERT((a == REG_DX) && (b == REG_AL), "Incorrect arguments to OUT instruction"); return __onebyte(__CONTEXT, 0xee); }
	__DEF_INSTR_2(out_8, ir, __IMM8, __REG) { (void)b; __CGX86_ASSERT(b == REG_AL, "Incorrect arguments to OUT instruction"); return __onebyte_imm8(__CONTEXT, 0xe6, a); }
	__DEF_INSTR_2(out_16, rr, __REG, __REG) { (void)a; (void)b; __CGX86_ASSERT((a == REG_DX) && (b == REG_AX), "Incorrect arguments to OUT instruction"); return __onebyte_opsz(__CONTEXT, 0xef); }
	__DEF_INSTR_2(out_16, ir, __IMM8, __REG) { (void)b; __CGX86_ASSERT(b == REG_AX, "Incorrect arguments to OUT instruction"); return __onebyte_opsz_imm8(__CONTEXT, 0xe7, a); }
	__DEF_INSTR_2(out_32, rr, __REG, __REG) { (void)a; (void)b; __CGX86_ASSERT((a == REG_DX) && (b == REG_EAX), "Incorrect arguments to OUT instruction"); return __onebyte(__CONTEXT, 0xef); }
	__DEF_INSTR_2(out_32, ir, __IMM8, __REG) { (void)b; __CGX86_ASSERT(b == REG_EAX, "Incorrect arguments to OUT instruction"); return __onebyte_imm8(__CONTEXT, 0xe7, a); }


	// Byte swap instruction
	__DEF_INSTR_1(bswap_32, r, __REG) { return __twobyte_opreg(__CONTEXT, 0xc8, __reg32(a)); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_1(bswap_64, r, __REG) { return __twobyte64_opreg(__CONTEXT, 0xc8, __reg64(a)); }
#endif


	// String instructions
	__ONEBYTE_INSTR(rep, 0xf3)
	__ONEBYTE_INSTR(repe, 0xf3)
	__ONEBYTE_INSTR(repz, 0xf3)
	__ONEBYTE_INSTR(repne, 0xf2)
	__ONEBYTE_INSTR(repnz, 0xf2)
	__ONEBYTE_INSTR(movsb, 0xa4)
	__ONEBYTE_OPSZ_INSTR(movsw, 0xa5)
	__ONEBYTE_INSTR(movsd, 0xa5)
	__ONEBYTE_INSTR(cmpsb, 0xa6)
	__ONEBYTE_OPSZ_INSTR(cmpsw, 0xa7)
	__ONEBYTE_INSTR(cmpsd, 0xa7)
	__ONEBYTE_INSTR(stosb, 0xaa)
	__ONEBYTE_OPSZ_INSTR(stosw, 0xab)
	__ONEBYTE_INSTR(stosd, 0xab)
	__ONEBYTE_INSTR(lodsb, 0xac)
	__ONEBYTE_OPSZ_INSTR(lodsw, 0xad)
	__ONEBYTE_INSTR(lodsd, 0xad)
	__ONEBYTE_INSTR(scasb, 0xae)
	__ONEBYTE_OPSZ_INSTR(scasw, 0xaf)
	__ONEBYTE_INSTR(scasd, 0xaf)
#ifdef __CODEGENX86_64BIT
	__ONEBYTE_INSTR_64(movsq, 0xa5)
	__ONEBYTE_INSTR_64(cmpsq, 0xa7)
	__ONEBYTE_INSTR_64(stosq, 0xab)
	__ONEBYTE_INSTR_64(lodsq, 0xad)
	__ONEBYTE_INSTR_64(scasq, 0xaf)
#endif


	// Floating point instructions
	__FPU_TWOBYTE_INSTR(fnop, 0xd9, 0xd0)
	__DEF_INSTR_1(fstenv, m, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0xd9, 6, __MEMOP(a), 0); }


	// SSE instructions
	__DEF_INSTR_2(movss, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf3, 0x10, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(movss, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf3, 0x10, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(movss, mr, __MEM, __REG) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf3, 0x11, __xmmreg(b), __MEMOP(a), 0); }
	__DEF_INSTR_2(movsd, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf2, 0x10, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(movsd, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf2, 0x10, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(movsd, mr, __MEM, __REG) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf2, 0x11, __xmmreg(b), __MEMOP(a), 0); }

	__DEF_INSTR_2(cvtss2sd, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf3, 0x5a, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(cvtss2sd, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf3, 0x5a, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(cvtsd2ss, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf2, 0x5a, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(cvtsd2ss, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf2, 0x5a, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(cvtsi2sd_32, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf2, 0x2a, __xmmreg(a), __reg32(b)); }
	__DEF_INSTR_2(cvtsi2sd_32, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf2, 0x2a, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(cvtsi2ss_32, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf3, 0x2a, __xmmreg(a), __reg32(b)); }
	__DEF_INSTR_2(cvtsi2ss_32, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf3, 0x2a, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(cvtsd2si_32, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf2, 0x2d, __reg32(a), __xmmreg(b)); }
	__DEF_INSTR_2(cvtsd2si_32, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf2, 0x2d, __reg32(a), __MEMOP(b), 0); }
#ifdef __CODEGENX86_64BIT
	__DEF_INSTR_2(cvtsi2sd_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64_prefix) (__CONTEXT, 0xf2, 0x2a, __xmmreg(a), __reg32(b)); }
	__DEF_INSTR_2(cvtsi2sd_64, rm, __REG, __MEM) { return __MODRM(mem_twobyte64_prefix) (__CONTEXT, 0xf2, 0x2a, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(cvtsi2ss_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64_prefix) (__CONTEXT, 0xf3, 0x2a, __xmmreg(a), __reg32(b)); }
	__DEF_INSTR_2(cvtsi2ss_64, rm, __REG, __MEM) { return __MODRM(mem_twobyte64_prefix) (__CONTEXT, 0xf3, 0x2a, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(cvtsd2si_64, rr, __REG, __REG) { return __MODRM(reg_twobyte64_prefix) (__CONTEXT, 0xf2, 0x2d, __reg64(a), __xmmreg(b)); }
	__DEF_INSTR_2(cvtsd2si_64, rm, __REG, __MEM) { return __MODRM(mem_twobyte64_prefix) (__CONTEXT, 0xf2, 0x2d, __reg64(a), __MEMOP(b), 0); }
#endif

	__DEF_INSTR_2(comiss, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0x2f, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(comiss, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0x2f, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(comisd, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0x66, 0x2f, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(comisd, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0x66, 0x2f, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(ucomiss, rr, __REG, __REG) { return __MODRM(reg_twobyte) (__CONTEXT, 0x2e, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(ucomiss, rm, __REG, __MEM) { return __MODRM(mem_twobyte) (__CONTEXT, 0x2e, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(ucomisd, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0x66, 0x2e, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(ucomisd, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0x66, 0x2e, __xmmreg(a), __MEMOP(b), 0); }

	__DEF_INSTR_2(addsd, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf2, 0x58, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(addsd, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf2, 0x58, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(subsd, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf2, 0x5c, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(subsd, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf2, 0x5c, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(mulsd, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf2, 0x59, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(mulsd, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf2, 0x59, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(divsd, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf2, 0x5e, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(divsd, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf2, 0x5e, __xmmreg(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(sqrtsd, rr, __REG, __REG) { return __MODRM(reg_twobyte_prefix) (__CONTEXT, 0xf2, 0x51, __xmmreg(a), __xmmreg(b)); }
	__DEF_INSTR_2(sqrtsd, rm, __REG, __MEM) { return __MODRM(mem_twobyte_prefix) (__CONTEXT, 0xf2, 0x51, __xmmreg(a), __MEMOP(b), 0); }

	__DEF_INSTR_3(roundsd, rri, __REG, __REG, __IMM8) { return __MODRM(reg_threebyte_imm8_prefix) (__CONTEXT, 0x66, 0x3a, 0x0b, __xmmreg(a), __xmmreg(b), c); }
	__DEF_INSTR_3(roundsd, rmi, __REG, __MEM, __IMM8) { return __MODRM(mem_threebyte_imm8_prefix) (__CONTEXT, 0x66, 0x3a, 0x0b, __xmmreg(a), __MEMOP(b), c); }


	// Misc instructions
#ifdef __CODEGENX86_32BIT
	__ONEBYTE_INSTR(daa, 0x27)
	__ONEBYTE_INSTR(das, 0x2f)
	__ONEBYTE_INSTR(aaa, 0x37)
	__ONEBYTE_INSTR(aas, 0x3f)
	__DEF_INSTR_2(bound_16, rm, __REG, __MEM) { return __MODRM(mem_onebyte_opsz) (__CONTEXT, 0x62, __reg16(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(bound_32, rm, __REG, __MEM) { return __MODRM(mem_onebyte) (__CONTEXT, 0x62, __reg32(a), __MEMOP(b), 0); }
	__DEF_INSTR_2(arpl, mr, __MEM, __REG) { return __MODRM(mem_onebyte) (__CONTEXT, 0x63, __reg16(b), __MEMOP(a), 0); }
#endif
	__ONEBYTE_INSTR(nop, 0x90)
	__ONEBYTE_OPSZ_INSTR(cbw, 0x98)
	__ONEBYTE_INSTR(cwde, 0x98)
	__ONEBYTE_OPSZ_INSTR(cwd, 0x99)
	__ONEBYTE_INSTR(cdq, 0x99)
#ifdef __CODEGENX86_64BIT
	__ONEBYTE_INSTR_64(cdqe, 0x98)
	__ONEBYTE_INSTR_64(cqo, 0x99)
#endif
	__ONEBYTE_INSTR(fwait, 0x9b)
	__ONEBYTE_INSTR(sahf, 0x9e)
	__ONEBYTE_INSTR(lahf, 0x9f)
#ifdef __CODEGENX86_32BIT
	__DEF_INSTR_1(aam, i, __IMM8) { return __onebyte_imm8(__CONTEXT, 0xd4, a); }
	__DEF_INSTR_1(aad, i, __IMM8) { return __onebyte_imm8(__CONTEXT, 0xd5, a); }
#endif
	__ONEBYTE_INSTR(xlat, 0xd7)
	__ONEBYTE_INSTR(hlt, 0xf4)
	__ONEBYTE_INSTR(cmc, 0xf5)
	__ONEBYTE_INSTR(clc, 0xf8)
	__ONEBYTE_INSTR(stc, 0xf9)
	__ONEBYTE_INSTR(cli, 0xfa)
	__ONEBYTE_INSTR(sti, 0xfb)
	__ONEBYTE_INSTR(cld, 0xfc)
	__ONEBYTE_INSTR(std, 0xfd)
	__TWOBYTE_INSTR(ud2, 0x0b);
	__TWOBYTE_INSTR(cpuid, 0xa2);
	__TWOBYTE_INSTR(syscall, 0x05);
	__TWOBYTE_INSTR(sysenter, 0x34);
	__TWOBYTE_INSTR(rdtsc, 0x31);


#ifdef __cplusplus
}
#endif

