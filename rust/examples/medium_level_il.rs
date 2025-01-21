use binaryninja::binary_view::{BinaryViewBase, BinaryViewExt};

fn main() {
    println!("Starting session...");
    // This loads all the core architecture, platform, etc plugins
    let headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    println!("Loading binary...");
    let bv = headless_session
        .load("/bin/cat")
        .expect("Couldn't open `/bin/cat`");

    println!("Filename:  `{}`", bv.file().filename());
    println!("File size: `{:#x}`", bv.len());
    println!("Function count: {}", bv.functions().len());

    for func in &bv.functions() {
        println!("{}:", func.symbol().full_name());

        let Ok(il) = func.medium_level_il() else {
            continue;
        };

        // Get the SSA form for this function
        let il = il.ssa_form();

        // Loop through all blocks in the function
        for block in il.basic_blocks().iter() {
            // Loop though each instruction in the block
            for instr in block.iter() {
                // Uplift the instruction into a native rust format
                let lifted = instr.lift();
                let address = instr.address;

                // Print the lifted instruction
                println!("{address:08x}: {lifted:#x?}");

                // Generically parse the IL tree and display the parts
                visitor::print_il_expr(&lifted, 2);
            }
        }
    }
}

mod visitor {
    use binaryninja::architecture::Intrinsic;
    use binaryninja::medium_level_il::MediumLevelILLiftedOperand::*;
    use binaryninja::medium_level_il::{MediumLevelILFunction, MediumLevelILLiftedInstruction};
    use binaryninja::variable::Variable;

    fn print_indent(indent: usize) {
        print!("{:<indent$}", "")
    }

    fn print_operation(operation: &MediumLevelILLiftedInstruction) {
        print!("{}", operation.name());
    }

    fn print_variable(func: &MediumLevelILFunction, var: &Variable) {
        print!("{}", func.function().variable_name(var));
    }

    pub(crate) fn print_il_expr(instr: &MediumLevelILLiftedInstruction, mut indent: usize) {
        print_indent(indent);
        print_operation(instr);

        println!();

        indent += 1;

        for (_name, operand) in instr.operands() {
            match operand {
                Int(int) => {
                    print_indent(indent);
                    println!("int 0x{:x}", int);
                }
                Float(float) => {
                    print_indent(indent);
                    println!("float {:e}", float);
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
                InstructionIndex(idx) => {
                    print_indent(indent);
                    println!("index {}", idx);
                }
            }
        }
    }
}
