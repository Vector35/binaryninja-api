use std::env;

use binaryninja::binaryview::BinaryViewExt;
use binaryninja::hlil::HighLevelILLiftedOperand;
use binaryninja::hlil::{HighLevelILFunction, HighLevelILLiftedInstruction};
use binaryninja::types::Variable;

fn print_indent(indent: usize) {
    print!("{:<indent$}", "")
}

fn print_operation(operation: &HighLevelILLiftedInstruction) {
    print!("{}", operation.name());
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
