## Warning 

Note that this project is no longer under active use. Binary Ninja does not use this for disassembly since August of 2018. 

# asmx86
This project is a disassembler library designed for emulation or automated analysis of x86 instructions. The primary output format of the disassembly is not text-based like most disassemblers. This library disassembles instructions to a structure containing the instruction mnemonic and the operands, which are in turn broken out into their components. Instruction mnemonics and operands are represented using an enumeration. This allows easier analysis or emulation of the instruction without costly parsing or string compares.

When it is necessary to disassemble to a string to display to a user, functions are provided to easily convert the structure form of an instruction to a string.

Also provided is an assembler library that is specifically designed to aid in the creation of run-time generated code.

### No dependencies
The asmx86 library does not have any external dependencies. It is a single C source file that can be included in any C or C++ project.

### Open source
Released under the [2-clause BSD license](http://opensource.org/licenses/BSD-2-Clause). Use it anywhere, even in a commercial product, for free.

### Thread-safe and allocation free
The asmx86 library is designed to be efficient. There are no dynamic allocations anywhere in the code, and it uses a minimal amount of stack space with a completely stateless design. It safe to call directly even from multiprocessor kernel code.

### Fast disassembly
A benchmark of text disassembly of 10 million instructions ran over 7 times faster than Capstone Engine. Structure-based disassembly is even faster and better aligned to the needs of emulation and automated analysis, as it provides the components of an instruction with no need for extra parsing.

## Disassembler API

### Instruction disassembly to structure
Disassembly can be performed using one of the following functions, depending on the target operating mode of the processor:

```
bool Disassemble16(const uint8_t* opcode,
                   uint64_t addr,
                   size_t maxLen,
                   Instruction* result);
bool Disassemble32(const uint8_t* opcode,
                   uint64_t addr,
                   size_t maxLen,
                   Instruction* result);
bool Disassemble64(const uint8_t* opcode,
                   uint64_t addr,
                   size_t maxLen,
                   Instruction* result);
```

Pass the bytes of the instruction as `opcode` and the length of this buffer as `maxLen`. Pass the address of the instruction on the target as `addr`. The results of the disassembly will be written to the `Instruction` structure pointed to by `result`.

These functions return `true` if a valid instruction was disassembled, and `false` otherwise.

### Convert structure disassembly to string

A function is also provided to convert an `Instruction` structure into a human readable string:

```
size_t FormatInstructionString(char* out,
                               size_t outMaxLen,
                               const char* fmt,
                               const uint8_t* opcode,
                               uint64_t addr,
                               const Instruction* instr);
```

Pass a pointer to the output buffer as `out` and the size of this buffer in characters as `outMaxLen`.

The `fmt` parameter contains a `printf`-like format string for displaying the instruction. The following format specifiers are defined:

* `%a`: Shows the address of the instruction as passed in the `addr` parameter.
* `%b`: Shows the bytes of the instruction. The `opcode` parameter should contain the same contents as the call to `Disassemble`.
* `%i`: Shows the instruction mnemonic.
* `%o`: Shows the operands.

Width specifiers are allowed on the format specifiers. For example, the `fmt` string `"%8a  %7i %o"` might show the following output:

```
08041a98  mov     eax, dword [ebp+0x14]
```

The `opcode` and `addr` parameters may be used by the format specifiers as described above. They are ignored if none of the provided format specifiers access them.

The `instr` parameter should be a pointer to an `Instruction` structure that was the result of a call to the `Disassemble` APIs.

This function returns the number of characters written.

### Instruction disassembly to string

Functions are provided to disassemble instructions directly to a human readable string. These functions will output the structure disassembly as well. They are effectively a combined call to the `Disassemble` and `FormatInstructionString` APIs.

```
size_t DisassembleToString16(char* out,
                             size_t outMaxLen,
                             const char* fmt,
                             const uint8_t* opcode,
                             uint64_t addr,
                             size_t maxLen,
                             Instruction* instr);
size_t DisassembleToString32(char* out,
                             size_t outMaxLen,
                             const char* fmt,
                             const uint8_t* opcode,
                             uint64_t addr,
                             size_t maxLen,
                             Instruction* instr);
size_t DisassembleToString64(char* out,
                             size_t outMaxLen,
                             const char* fmt,
                             const uint8_t* opcode,
                             uint64_t addr,
                             size_t maxLen,
                             Instruction* instr);
```

The `out`, `outMaxLen`, and `fmt` parameters are the same as the `FormatInstructionString` function, see the above documentation.

The `opcode` parameter is required and should contain the bytes of the instruction to disassemble, and the length of this buffer should be passed as `maxLen`. Pass the address of the instruction on the target as `addr`.

The `instr` parameter is required and the provided `Instruction` structure will be written with the results of the disassembly.

These functions return the number of characters written, or zero if the instruction is invalid.

### The `Instruction` structure

Disassembly results are typically written to an `Instruction` structure, which is defined as follows:

```
struct Instruction
{
    InstructionOperation operation;
    InstructionOperand operands[3];
    uint32_t flags;
    SegmentRegister segment;
    size_t length;
};
```

The `operation` member is an enumeration which matches the name of the instruction mnemonic. See the header file for a full listing of the supported instructions.

The `operands` array contains the operands to the instruction. Each operand is a structure and is defined below.

The `flags` member is a bit field that may contain one of more of the following flags:

* `X86_FLAG_LOCK`: The lock prefix was provided to this instruction.
* `X86_FLAG_REP`: This instruction is an unconditional repeated string instruction.
* `X86_FLAG_REPNE`: The repeated string instruction is conditional and uses the `REPNE` prefix.
* `X86_FLAG_REPE`: The repeated string instruction is conditional and uses the `REPE` prefix.
* `X86_FLAG_ANY_REP`: The instruction is any repeated string instruction.
* `X86_FLAG_OPSIZE`: The operand size prefix was used.
* `X86_FLAG_ADDRSIZE`: The address size prefix was used.
* `X86_FLAG_INSUFFICIENT_LENGTH`: The instruction may be valid but an insufficient number of bytes were provided. The `Disassemble` function will return `false` when this flag is set.

The `segment` member contains the segment prefix, if any. This will be either `SEG_DEFAULT` or a segment register (e.g. `SEG_ES`).

The `length` member contains the length of the instruction in bytes. This can be used to continue disassembling at the next instruction. Be sure to check the return value of `Disassemble` as an invalid instruction may leave a zero here.

Each operand is described by the structure below:

```
struct InstructionOperand
{
    OperandType operand;
    OperandType components[2];
    uint8_t scale;
    uint16_t size;
    int64_t immediate;
    SegmentRegister segment;
};
```

The `operand` member is an enumeration that contains the operand. This may be a register, or one of the following special enumeration members:

* `NONE`: The operand is invalid.
* `IMM`: The operand is a constant integer. See the `immediate` member.
* `MEM`: The operand is a memory reference.

If the `operand` member is `NONE`, none of the other members are defined. Otherwise, the `size` member contains the size in bytes of the operand. If the `operand` member is `IMM`, the `immediate` member is also defined. If the `operand` member is `MEM`, all other members are defined as below.

The `components` member contains the address components of a memory operand. The first element is never scaled, and the second element is multiplied by the `scale` member. Any element can be `NONE`, which can be represented as a constant zero. If the element is not `NONE`, it will be a register.

The `size` member contains the size of the operand in bytes. For register operands, this is the size of the register. For memory operands, this is the size of the memory access.

The `immediate` member contains the value of a constant integer when the operand is the `IMM` type. When the operand is a memory reference, the `immediate` member contains a constant offset for the memory reference.

The `segment` member contains the segment register that will be used for a memory access. This will always contain a segment register, as `SEG_DEFAULT` is resolved to the default register.

For memory references, the address of the memory reference is effectively the following formula, where references to the `component` array should look up the current value of the register or substitute zero if the value is `NONE`:

```
address = components[0] + components[1] * scale + immediate
```

## Assembler API

The asmx86 library also provides an assembler library for emitting run-time generated code. It is designed to emit machine code using an easy-to-read API without going through any kind of string parsing. The compiled code is very close to the performance of writing machine code manually into a buffer.

The following is a simple example of how to write code into a buffer:

```
uint8_t* code = allocate();
X86_DECLARE_JUMP_LABEL(loop);
code += X86_EMIT64_R(code, push, REG_RBP);
code += X86_EMIT64_RR(code, mov_64, REG_RBP, REG_RSP);
code += X86_EMIT64_RI(code, sub_64, REG_RSP, 0x8);
code += X86_EMIT64_MR(code, mov_32, X86_MEM(REG_RBP, -0x8), REG_EDI);
code += X86_EMIT64_MR(code, mov_32, X86_MEM(REG_RBP, -0x4), REG_ESI);
code += X86_EMIT64_RR(code, xor_32, REG_EAX, REG_EAX);
code += X86_EMIT64_RM(code, mov_32, REG_ECX, X86_MEM(REG_RBP, -0x8));
code += X86_EMIT64_RM(code, mov_32, REG_EDX, X86_MEM(REG_RBP, -0x4));
X86_MARK_JUMP_LABEL_64(code, loop);
code += X86_EMIT64_RR(code, add_32, REG_EAX, REG_EDX);
code += X86_EMIT64_R(code, inc_32, REG_EDX);
code += X86_EMIT64_R(code, dec_32, REG_ECX);
code += X86_EMIT64_T(code, jnz, loop);
code += X86_EMIT64_RR(code, mov_64, REG_RSP, REG_RBP);
code += X86_EMIT64_R(code, pop, REG_RBP);
code += X86_EMIT64(code, retn);
```

This emits a function to a buffer, which can then be executed by the processor. Often it is not possible to know the maximum size of the code before emitting it, so another set of APIs is available to allow dynamic allocation of buffer space as it is needed.

These APIs are prefixed by `DYNALLOC`, for example:

```
X86_DYNALLOC_EMIT64_R(buffer, AllocSpaceForInstr, AdvanceForInstr,
                      push, REG_RBP);
```

The `AllocSpaceForInstr` and `AdvanceForInstr` parameters are to be provided by the caller, and manage the buffer provided. The buffer passed can be any type of object (including a C++ class instance), which the functions provided can use as context to manage the buffer.

The `AllocSpaceForInstr` function should have the following prototype (the name can be chosen by the caller):

```
uint8_t* AllocSpaceForInstr(void* buffer, size_t length);
```

This function will be called with the `buffer` parameter equal to the `EMIT` call, and the length of the instruction that is to be written. This function can perform any buffer management necessary, such as allocating extra space and emitting an unconditional jump instruction to the new buffer space. It should return a pointer to where the instruction should be written, and must have at least `length` bytes available for writing. The actual instruction written may not be as long as the length given, as some instruction lengths are dependent on the address of the instruction. It will never be longer than the length provided.

The `AdvanceForInstr` function should have the following prototype:

```
void AdvanceForInstr(void* buffer, size_t length);
```

This function will be called after an instruction is written to the buffer. The `buffer` parameter will be equal to the one provided in the `EMIT` call, and the `length` parameter is the actual length of the instruction written (which may be less than the `length` parameter passed to the `AllocSpaceForInstr` function). The buffer management function can perform any updates necessary to mark the instruction as written and ensure that the next instruction will be written to the correct location following the one written.

Instructions that have been written to buffers should not be moved in any way until all labels have been resolved. The label API internally keeps pointers to the instructions until they are resolved.

It is recommended to define a set of pass-through macros that provide the necessary functions to the API automatically, such that the caller can write code like this:

```
CodeBufferObject buffer;
EMIT_RR(&buffer, mov_64, REG_RAX, REG_RDI);
EMIT_RR(&buffer, add_64, REG_RAX, REG_RSI);
EMIT(&buffer, retn);
buffer.Finalize();
```

This API is not provided by asmx86, as it is dependent on the host system's memory management system, but demonstrates the intended use of the `DYNALLOC` set of APIs. The `EMIT_RR` and `EMIT` macros shown above should be written to resolve to something like the following:

```
X86_DYNALLOC_EMIT64_RR(&buffer,
                       CodeBufferObject::AllocSpaceForInstr,
                       CodeBufferObject::AdvanceForInstr,
                       mov_64, REG_RAX, REG_RDI);
X86_DYNALLOC_EMIT64_RR(&buffer,
                       CodeBufferObject::AllocSpaceForInstr,
                       CodeBufferObject::AdvanceForInstr,
                       add_64, REG_RAX, REG_RSI);
X86_DYNALLOC_EMIT64(&buffer,
                    CodeBufferObject::AllocSpaceForInstr,
                    CodeBufferObject::AdvanceForInstr,
                    retn);
```
