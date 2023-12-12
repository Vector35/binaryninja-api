use std::env;

use binaryninja::binaryview::BinaryViewExt;
use binaryninja::hlil::operation::HighLevelILOperand;
use binaryninja::hlil::{HighLevelILFunction, HighLevelILInstruction};
use binaryninja::types::Variable;

fn print_indent(indent: usize) {
    print!("{:<indent$}", "")
}

fn print_operation(operation: &HighLevelILInstruction) {
    use HighLevelILInstruction::*;
    match operation {
        Adc(_op) => print!("Adc"),
        Sbb(_op) => print!("Sbb"),
        Rlc(_op) => print!("Rlc"),
        Rrc(_op) => print!("Rrc"),
        Add(_op) => print!("Add"),
        Sub(_op) => print!("Sub"),
        And(_op) => print!("And"),
        Or(_op) => print!("Or"),
        Xor(_op) => print!("Xor"),
        Lsl(_op) => print!("Lsl"),
        Lsr(_op) => print!("Lsr"),
        Asr(_op) => print!("Asr"),
        Rol(_op) => print!("Rol"),
        Ror(_op) => print!("Ror"),
        Mul(_op) => print!("Mul"),
        MuluDp(_op) => print!("MuluDp"),
        MulsDp(_op) => print!("MulsDp"),
        Divu(_op) => print!("Divu"),
        DivuDp(_op) => print!("DivuDp"),
        Divs(_op) => print!("Divs"),
        DivsDp(_op) => print!("DivsDp"),
        Modu(_op) => print!("Modu"),
        ModuDp(_op) => print!("ModuDp"),
        Mods(_op) => print!("Mods"),
        ModsDp(_op) => print!("ModsDp"),
        CmpE(_op) => print!("CmpE"),
        CmpNe(_op) => print!("CmpNe"),
        CmpSlt(_op) => print!("CmpSlt"),
        CmpUlt(_op) => print!("CmpUlt"),
        CmpSle(_op) => print!("CmpSle"),
        CmpUle(_op) => print!("CmpUle"),
        CmpSge(_op) => print!("CmpSge"),
        CmpUge(_op) => print!("CmpUge"),
        CmpSgt(_op) => print!("CmpSgt"),
        CmpUgt(_op) => print!("CmpUgt"),
        TestBit(_op) => print!("TestBit"),
        AddOverflow(_op) => print!("AddOverflow"),
        Fadd(_op) => print!("Fadd"),
        Fsub(_op) => print!("Fsub"),
        Fmul(_op) => print!("Fmul"),
        Fdiv(_op) => print!("Fdiv"),
        FcmpE(_op) => print!("FcmpE"),
        FcmpNe(_op) => print!("FcmpNe"),
        FcmpLt(_op) => print!("FcmpLt"),
        FcmpLe(_op) => print!("FcmpLe"),
        FcmpGe(_op) => print!("FcmpGe"),
        FcmpGt(_op) => print!("FcmpGt"),
        FcmpO(_op) => print!("FcmpO"),
        FcmpUo(_op) => print!("FcmpUo"),
        ArrayIndex(_op) => print!("ArrayIndex"),
        ArrayIndexSsa(_op) => print!("ArrayIndexSsa"),
        Assign(_op) => print!("Assign"),
        AssignMemSsa(_op) => print!("AssignMemSsa"),
        AssignUnpack(_op) => print!("AssignUnpack"),
        AssignUnpackMemSsa(_op) => print!("AssignUnpackMemSsa"),
        Block(_op) => print!("Block"),
        Call(_op) => print!("Call"),
        Tailcall(_op) => print!("Tailcall"),
        CallSsa(_op) => print!("CallSsa"),
        Case(_op) => print!("Case"),
        Const(_op) => print!("Const"),
        ConstPtr(_op) => print!("ConstPtr"),
        Import(_op) => print!("Import"),
        ConstData(_op) => print!("ConstData"),
        Deref(_op) => print!("Deref"),
        AddressOf(_op) => print!("AddressOf"),
        Neg(_op) => print!("Neg"),
        Not(_op) => print!("Not"),
        Sx(_op) => print!("Sx"),
        Zx(_op) => print!("Zx"),
        LowPart(_op) => print!("LowPart"),
        BoolToInt(_op) => print!("BoolToInt"),
        UnimplMem(_op) => print!("UnimplMem"),
        Fsqrt(_op) => print!("Fsqrt"),
        Fneg(_op) => print!("Fneg"),
        Fabs(_op) => print!("Fabs"),
        FloatToInt(_op) => print!("FloatToInt"),
        IntToFloat(_op) => print!("IntToFloat"),
        FloatConv(_op) => print!("FloatConv"),
        RoundToInt(_op) => print!("RoundToInt"),
        Floor(_op) => print!("Floor"),
        Ceil(_op) => print!("Ceil"),
        Ftrunc(_op) => print!("Ftrunc"),
        DerefFieldSsa(_op) => print!("DerefFieldSsa"),
        DerefSsa(_op) => print!("DerefSsa"),
        ExternPtr(_op) => print!("ExternPtr"),
        FloatConst(_op) => print!("FloatConst"),
        For(_op) => print!("For"),
        ForSsa(_op) => print!("ForSsa"),
        Goto(_op) => print!("Goto"),
        Label(_op) => print!("Label"),
        If(_op) => print!("If"),
        Intrinsic(_op) => print!("Intrinsic"),
        IntrinsicSsa(_op) => print!("IntrinsicSsa"),
        Jump(_op) => print!("Jump"),
        MemPhi(_op) => print!("MemPhi"),
        Nop(_op) => print!("Nop"),
        Break(_op) => print!("Break"),
        Continue(_op) => print!("Continue"),
        Noret(_op) => print!("Noret"),
        Unreachable(_op) => print!("Unreachable"),
        Bp(_op) => print!("Bp"),
        Undef(_op) => print!("Undef"),
        Unimpl(_op) => print!("Unimpl"),
        Ret(_op) => print!("Ret"),
        Split(_op) => print!("Split"),
        StructField(_op) => print!("StructField"),
        DerefField(_op) => print!("DerefField"),
        Switch(_op) => print!("Switch"),
        Syscall(_op) => print!("Syscall"),
        SyscallSsa(_op) => print!("SyscallSsa"),
        Trap(_op) => print!("Trap"),
        VarDeclare(_op) => print!("VarDeclare"),
        Var(_op) => print!("Var"),
        VarInit(_op) => print!("VarInit"),
        VarInitSsa(_op) => print!("VarInitSsa"),
        VarPhi(_op) => print!("VarPhi"),
        VarSsa(_op) => print!("VarSsa"),
        While(_op) => print!("While"),
        DoWhile(_op) => print!("DoWhile"),
        WhileSsa(_op) => print!("WhileSsa"),
        DoWhileSsa(_op) => print!("DoWhileSsa"),
    }
}

fn print_variable(func: &HighLevelILFunction, var: &Variable) {
    print!("{}", func.get_function().get_variable_name(var));
}

fn print_il_expr(instr: &HighLevelILInstruction, mut indent: usize) {
    print_indent(indent);
    print_operation(instr);
    println!("");

    indent += 1;

    use HighLevelILOperand::*;
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
                print_il_expr(&instr, 2);
            }
        }
        println!();
    }

    // Important!  Standalone executables need to call shutdown or they will hang forever
    binaryninja::headless::shutdown();
}
