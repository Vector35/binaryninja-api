use std::env;

use binaryninja::binaryview::BinaryViewExt;
use binaryninja::mlil::MediumLevelILLiftedOperand;
use binaryninja::mlil::{MediumLevelILFunction, MediumLevelILLiftedInstruction};
use binaryninja::types::Variable;

fn print_indent(indent: usize) {
    print!("{:<indent$}", "")
}

fn print_operation(operation: &MediumLevelILLiftedInstruction) {
    print!("{}", operation.name());
}

fn print_variable(func: &MediumLevelILFunction, var: &Variable) {
    print!("{}", func.get_function().get_variable_name(var));
}

fn print_il_expr(instr: &MediumLevelILLiftedInstruction, mut indent: usize) {
    print_indent(indent);
    print_operation(instr);
    println!("");

    indent += 1;

    use MediumLevelILLiftedOperand::*;
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
            VarList(list) => {
                print_indent(indent);
                print!("var list ");
                for i in list {
                    print_variable(&instr.function, &i);
                    print!(" ");
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
                print_il_expr(&instr.lift(), 2);
            }
        }
        println!();
    }
}
