use binaryninja::architecture::Architecture;
use binaryninja::binaryview::{BinaryViewBase, BinaryViewExt};

// Standalone executables need to provide a main function for rustc
// Plugins should refer to `binaryninja::command::*` for the various registration callbacks.
fn main() {
    // This loads all the core architecture, platform, etc plugins
    // Standalone executables probably need to call this, but plugins do not
    println!("Loading plugins...");
    binaryninja::headless::init();

    // Your code here...
    println!("Loading binary...");
    let bv = binaryninja::open_view("/bin/cat").expect("Couldn't open `/bin/cat`");

    println!("Filename:  `{}`", bv.file().filename());
    println!("File size: `{:#x}`", bv.len());
    println!("Function count: {}", bv.functions().len());

    for func in &bv.functions() {
        println!("  `{}`:", func.symbol().full_name());
        for basic_block in &func.basic_blocks() {
            // TODO : This is intended to be refactored to be more nice to work with soon(TM)
            for addr in basic_block.as_ref() {
                print!("    {}  ", addr);
                match func.arch().instruction_text(
                    bv.read_buffer(addr, func.arch().max_instr_len())
                        .unwrap()
                        .get_data(),
                    addr,
                ) {
                    Some((_, tokens)) => {
                        tokens
                            .iter()
                            .for_each(|token| print!("{}", token.text().as_str()));
                        println!("")
                    }
                    _ => (),
                }
            }
        }
    }

    // Important!  Standalone executables need to call shutdown or they will hang forever
    binaryninja::headless::shutdown();
}
