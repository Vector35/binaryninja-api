use std::env;

use binaryninja::binaryview::BinaryViewExt;
use binaryninja::mlil::operation::MediumLevelILOperand;
use binaryninja::mlil::{MediumLevelILFunction, MediumLevelILInstruction};
use binaryninja::types::Variable;

fn print_indent(indent: usize) {
    print!("{:<indent$}", "")
}

fn print_operation(operation: &MediumLevelILInstruction) {
    use MediumLevelILInstruction::*;
    match operation {
        Nop(_) => print!("Nop"),
        Noret(_) => print!("Noret"),
        Bp(_) => print!("Bp"),
        Undef(_) => print!("Undef"),
        Unimpl(_) => print!("Unimpl"),
        If(_) => print!("If"),
        FloatConst(_) => print!("FloatConst"),
        Const(_) => print!("Const"),
        ConstPtr(_) => print!("ConstPtr"),
        Import(_) => print!("Import"),
        ExternPtr(_) => print!("ExternPtr"),
        ConstData(_) => print!("ConstData"),
        Jump(_) => print!("Jump"),
        RetHint(_) => print!("RetHint"),
        StoreSsa(_) => print!("StoreSsa"),
        StoreStructSsa(_) => print!("StoreStructSsa"),
        StoreStruct(_) => print!("StoreStruct"),
        Store(_) => print!("Store"),
        JumpTo(_) => print!("JumpTo"),
        Goto(_) => print!("Goto"),
        FreeVarSlot(_) => print!("FreeVarSlot"),
        SetVarField(_) => print!("SetVarField"),
        SetVar(_) => print!("SetVar"),
        FreeVarSlotSsa(_) => print!("FreeVarSlotSsa"),
        SetVarSsaField(_) => print!("SetVarSsaField"),
        SetVarAliasedField(_) => print!("SetVarAliasedField"),
        SetVarAliased(_) => print!("SetVarAliased"),
        SetVarSsa(_) => print!("SetVarSsa"),
        VarPhi(_) => print!("VarPhi"),
        MemPhi(_) => print!("MemPhi"),
        VarSplit(_) => print!("VarSplit"),
        SetVarSplit(_) => print!("SetVarSplit"),
        VarSplitSsa(_) => print!("VarSplitSsa"),
        SetVarSplitSsa(_) => print!("SetVarSplitSsa"),
        Add(_) => print!("Add"),
        Sub(_) => print!("Sub"),
        And(_) => print!("And"),
        Or(_) => print!("Or"),
        Xor(_) => print!("Xor"),
        Lsl(_) => print!("Lsl"),
        Lsr(_) => print!("Lsr"),
        Asr(_) => print!("Asr"),
        Rol(_) => print!("Rol"),
        Ror(_) => print!("Ror"),
        Mul(_) => print!("Mul"),
        MuluDp(_) => print!("MuluDp"),
        MulsDp(_) => print!("MulsDp"),
        Divu(_) => print!("Divu"),
        DivuDp(_) => print!("DivuDp"),
        Divs(_) => print!("Divs"),
        DivsDp(_) => print!("DivsDp"),
        Modu(_) => print!("Modu"),
        ModuDp(_) => print!("ModuDp"),
        Mods(_) => print!("Mods"),
        ModsDp(_) => print!("ModsDp"),
        CmpE(_) => print!("CmpE"),
        CmpNe(_) => print!("CmpNe"),
        CmpSlt(_) => print!("CmpSlt"),
        CmpUlt(_) => print!("CmpUlt"),
        CmpSle(_) => print!("CmpSle"),
        CmpUle(_) => print!("CmpUle"),
        CmpSge(_) => print!("CmpSge"),
        CmpUge(_) => print!("CmpUge"),
        CmpSgt(_) => print!("CmpSgt"),
        CmpUgt(_) => print!("CmpUgt"),
        TestBit(_) => print!("TestBit"),
        AddOverflow(_) => print!("AddOverflow"),
        FcmpE(_) => print!("FcmpE"),
        FcmpNe(_) => print!("FcmpNe"),
        FcmpLt(_) => print!("FcmpLt"),
        FcmpLe(_) => print!("FcmpLe"),
        FcmpGe(_) => print!("FcmpGe"),
        FcmpGt(_) => print!("FcmpGt"),
        FcmpO(_) => print!("FcmpO"),
        FcmpUo(_) => print!("FcmpUo"),
        Fadd(_) => print!("Fadd"),
        Fsub(_) => print!("Fsub"),
        Fmul(_) => print!("Fmul"),
        Fdiv(_) => print!("Fdiv"),
        Adc(_) => print!("Adc"),
        Sbb(_) => print!("Sbb"),
        Rlc(_) => print!("Rlc"),
        Rrc(_) => print!("Rrc"),
        Call(_) => print!("Call"),
        Tailcall(_) => print!("Tailcall"),
        Syscall(_) => print!("Syscall"),
        Intrinsic(_) => print!("Intrinsic"),
        IntrinsicSsa(_) => print!("IntrinsicSsa"),
        CallSsa(_) => print!("CallSsa"),
        TailcallSsa(_) => print!("TailcallSsa"),
        CallUntypedSsa(_) => print!("CallUntypedSsa"),
        TailcallUntypedSsa(_) => print!("TailcallUntypedSsa"),
        SyscallSsa(_) => print!("SyscallSsa"),
        SyscallUntypedSsa(_) => print!("SyscallUntypedSsa"),
        CallUntyped(_) => print!("CallUntyped"),
        TailcallUntyped(_) => print!("TailcallUntyped"),
        SyscallUntyped(_) => print!("SyscallUntyped"),
        SeparateParamList(_) => print!("SeparateParamList"),
        SharedParamSlot(_) => print!("SharedParamSlot"),
        Neg(_) => print!("Neg"),
        Not(_) => print!("Not"),
        Sx(_) => print!("Sx"),
        Zx(_) => print!("Zx"),
        LowPart(_) => print!("LowPart"),
        BoolToInt(_) => print!("BoolToInt"),
        UnimplMem(_) => print!("UnimplMem"),
        Fsqrt(_) => print!("Fsqrt"),
        Fneg(_) => print!("Fneg"),
        Fabs(_) => print!("Fabs"),
        FloatToInt(_) => print!("FloatToInt"),
        IntToFloat(_) => print!("IntToFloat"),
        FloatConv(_) => print!("FloatConv"),
        RoundToInt(_) => print!("RoundToInt"),
        Floor(_) => print!("Floor"),
        Ceil(_) => print!("Ceil"),
        Ftrunc(_) => print!("Ftrunc"),
        Load(_) => print!("Load"),
        LoadStruct(_) => print!("LoadStruct"),
        LoadStructSsa(_) => print!("LoadStructSsa"),
        LoadSsa(_) => print!("LoadSsa"),
        Ret(_) => print!("Ret"),
        Var(_) => print!("Var"),
        AddressOf(_) => print!("AddressOf"),
        VarField(_) => print!("VarField"),
        AddressOfField(_) => print!("AddressOfField"),
        VarSsa(_) => print!("VarSsa"),
        VarAliased(_) => print!("VarAliased"),
        VarSsaField(_) => print!("VarSsaField"),
        VarAliasedField(_) => print!("VarAliasedField"),
        Trap(_) => print!("Trap"),
    }
}

fn print_variable(func: &MediumLevelILFunction, var: &Variable) {
    print!("{}", func.get_function().get_variable_name(var));
}

fn print_il_expr(instr: &MediumLevelILInstruction, mut indent: usize) {
    print_indent(indent);
    print_operation(instr);
    println!("");

    indent += 1;

    use MediumLevelILOperand::*;
    for (_name, operand) in instr.operands() {
        match operand {
            Int(int) => {
                print_indent(indent);
                println!("int 0x{:x}", int);
            }
            Float(float) => {
                print_indent(indent);
                println!("int {:e}", float);
            }
            Expr(expr) => print_il_expr(&expr, indent),
            Var(var) => {
                print_indent(indent);
                print!("var ");
                print_variable(instr.function(), &var);
                println!();
            }
            VarSsa(var) => {
                print_indent(indent);
                print!("ssa var ");
                print_variable(instr.function(), &var.variable);
                println!("#{}", var.version);
            }
            IntList(list) => {
                print_indent(indent);
                print!("index list ");
                for i in list {
                    print!("{i} ");
                }
                println!();
            }
            VarList(list) => {
                print_indent(indent);
                print!("var list ");
                for i in list {
                    print_variable(instr.function(), &i);
                    print!(" ");
                }
                println!();
            }
            VarSsaList(list) => {
                print_indent(indent);
                print!("ssa var list ");
                for i in list {
                    print_variable(instr.function(), &i.variable);
                    print!("#{} ", i.version);
                }
                println!();
            }
            ExprList(list) => {
                print_indent(indent);
                println!("expr list");
                for i in list {
                    print_il_expr(&i, indent + 1);
                }
            }
            TargetMap(list) => {
                print_indent(indent);
                print!("target map ");
                for (i, f) in list {
                    print!("({i}, {f})  ");
                }
                println!();
            }
            ConstantData(_) => println!("contantdata"),
            Intrinsic(intrinsic) => println!("intrinsic {}", intrinsic.name()),
        }
    }
}

// Standalone executables need to provide a main function for rustc
// Plugins should refer to `binaryninja::command::*` for the various registration callbacks.
fn main() {
    let mut args = env::args();
    let _ = args.next().unwrap();
    let Some(filename) = args.next() else {
        panic!("Expected input filename\n");
    };

    // This loads all the core architecture, platform, etc plugins
    // Standalone executables probably need to call this, but plugins do not
    println!("Loading plugins...");
    let _headless_session = binaryninja::headless::Session::new();

    // Your code here...
    println!("Loading binary...");
    let bv = binaryninja::load(filename).expect("Couldn't open binary file");

    // Go through all functions in the binary
    for func in bv.functions().iter() {
        let sym = func.symbol();
        println!("Function {}:", sym.full_name());

        let Ok(il) = func.medium_level_il() else {
            println!("    Does not have MLIL\n");
            continue;
        };

        // Loop through all blocks in the function
        for block in il.basic_blocks().iter() {
            // Loop though each instruction in the block
            for instr in block.iter() {
                // Generically parse the IL tree and display the parts
                print_il_expr(&instr, 2);
            }
        }
        println!();
    }
}
