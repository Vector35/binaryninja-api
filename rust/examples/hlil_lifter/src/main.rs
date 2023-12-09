use std::env;

use binaryninja::binaryview::BinaryViewExt;

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
        // Get the SSA form for this function
        let il = il.ssa_form();

        // Loop through all blocks in the function
        for block in il.basic_blocks().iter() {
            // Loop though each instruction in the block
            for instr in block.iter() {
                // Uplift the instruction into a native rust format
                let lifted = instr.lift();
                let address = instr.address();

                // print the lifted instruction
                println!("{address:08x}: {lifted:x?}");
            }
        }
        println!();
    }

    // Important!  Standalone executables need to call shutdown or they will hang forever
    binaryninja::headless::shutdown();
}
