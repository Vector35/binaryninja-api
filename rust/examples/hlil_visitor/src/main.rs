use std::env;

use binaryninja::binaryview::BinaryViewExt;
use binaryninja::hlil::HighLevelILLiftedOperand;
use binaryninja::hlil::{
    HighLevelILFunction, HighLevelILLiftedInstruction, HighLevelILLiftedInstructionKind,
};
use binaryninja::types::Variable;

fn print_indent(indent: usize) {
    print!("{:<indent$}", "")
}

fn print_operation(operation: &HighLevelILLiftedInstruction) {
    use HighLevelILLiftedInstructionKind::*;
    match &operation.kind {
        Adc(_) => print!("Adc"),
        Sbb(_) => print!("Sbb"),
        Rlc(_) => print!("Rlc"),
        Rrc(_) => print!("Rrc"),
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
        Fadd(_) => print!("Fadd"),
        Fsub(_) => print!("Fsub"),
        Fmul(_) => print!("Fmul"),
        Fdiv(_) => print!("Fdiv"),
        FcmpE(_) => print!("FcmpE"),
        FcmpNe(_) => print!("FcmpNe"),
        FcmpLt(_) => print!("FcmpLt"),
        FcmpLe(_) => print!("FcmpLe"),
        FcmpGe(_) => print!("FcmpGe"),
        FcmpGt(_) => print!("FcmpGt"),
        FcmpO(_) => print!("FcmpO"),
        FcmpUo(_) => print!("FcmpUo"),
        ArrayIndex(_) => print!("ArrayIndex"),
        ArrayIndexSsa(_) => print!("ArrayIndexSsa"),
        Assign(_) => print!("Assign"),
        AssignMemSsa(_) => print!("AssignMemSsa"),
        AssignUnpack(_) => print!("AssignUnpack"),
        AssignUnpackMemSsa(_) => print!("AssignUnpackMemSsa"),
        Block(_) => print!("Block"),
        Call(_) => print!("Call"),
        Tailcall(_) => print!("Tailcall"),
        CallSsa(_) => print!("CallSsa"),
        Case(_) => print!("Case"),
        Const(_) => print!("Const"),
        ConstPtr(_) => print!("ConstPtr"),
        Import(_) => print!("Import"),
        ConstData(_) => print!("ConstData"),
        Deref(_) => print!("Deref"),
        AddressOf(_) => print!("AddressOf"),
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
        DerefFieldSsa(_) => print!("DerefFieldSsa"),
        DerefSsa(_) => print!("DerefSsa"),
        ExternPtr(_) => print!("ExternPtr"),
        FloatConst(_) => print!("FloatConst"),
        For(_) => print!("For"),
        ForSsa(_) => print!("ForSsa"),
        Goto(_) => print!("Goto"),
        Label(_) => print!("Label"),
        If(_) => print!("If"),
        Intrinsic(_) => print!("Intrinsic"),
        IntrinsicSsa(_) => print!("IntrinsicSsa"),
        Jump(_) => print!("Jump"),
        MemPhi(_) => print!("MemPhi"),
        Nop => print!("Nop"),
        Break => print!("Break"),
        Continue => print!("Continue"),
        Noret => print!("Noret"),
        Unreachable => print!("Unreachable"),
        Bp => print!("Bp"),
        Undef => print!("Undef"),
        Unimpl => print!("Unimpl"),
        Ret(_) => print!("Ret"),
        Split(_) => print!("Split"),
        StructField(_) => print!("StructField"),
        DerefField(_) => print!("DerefField"),
        Switch(_) => print!("Switch"),
        Syscall(_) => print!("Syscall"),
        SyscallSsa(_) => print!("SyscallSsa"),
        Trap(_) => print!("Trap"),
        VarDeclare(_) => print!("VarDeclare"),
        Var(_) => print!("Var"),
        VarInit(_) => print!("VarInit"),
        VarInitSsa(_) => print!("VarInitSsa"),
        VarPhi(_) => print!("VarPhi"),
        VarSsa(_) => print!("VarSsa"),
        While(_) => print!("While"),
        DoWhile(_) => print!("DoWhile"),
        WhileSsa(_) => print!("WhileSsa"),
        DoWhileSsa(_) => print!("DoWhileSsa"),
    }
}

fn print_variable(func: &HighLevelILFunction, var: &Variable) {
    print!("{}", func.get_function().get_variable_name(var));
}

fn print_il_expr(instr: &HighLevelILLiftedInstruction, mut indent: usize) {
    print_indent(indent);
    print_operation(instr);
    println!("");

    indent += 1;

    use HighLevelILLiftedOperand::*;
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
                print_variable(&instr.function, &var);
                println!();
            }
            VarSsa(var) => {
                print_indent(indent);
                print!("ssa var ");
                print_variable(&instr.function, &var.variable);
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
            VarSsaList(list) => {
                print_indent(indent);
                print!("ssa var list ");
                for i in list {
                    print_variable(&instr.function, &i.variable);
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
            Label(label) => println!("label {}", label.name()),
            MemberIndex(mem_idx) => println!("member_index {:?}", mem_idx),
            ConstantData(_) => println!("constant_data TODO"),
            Intrinsic(_) => println!("intrinsic TODO"),
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
    binaryninja::headless::init();

    // Your code here...
    println!("Loading binary...");
    let bv = binaryninja::load(filename).expect("Couldn't open binary file");

    // Go through all functions in the binary
    for func in bv.functions().iter() {
        let sym = func.symbol();
        println!("Function {}:", sym.full_name());

        let Ok(il) = func.high_level_il(true) else {
            println!("    Does not have HLIL\n");
            continue;
        };

        // Loop through all blocks in the function
        for block in il.basic_blocks().iter() {
            // Loop though each instruction in the block
            for instr in block.iter() {
                // Generically parse the IL tree and display the parts
                print_il_expr(&instr.lift(), 2);
            }
        }
        println!();
    }

    // Important!  Standalone executables need to call shutdown or they will hang forever
    binaryninja::headless::shutdown();
}
