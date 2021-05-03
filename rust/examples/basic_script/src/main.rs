use binaryninja::architecture::Architecture;
use binaryninja::binaryview::{BinaryViewBase, BinaryViewExt};

fn main() {
    println!("Loading plugins..."); // This loads all the core architecture, platform, etc plugins
    binaryninja::headless::init();

    println!("Loading binary...");
    let bv = binaryninja::open_view("/bin/cat").expect("Couldn't open `/bin/cat`");

    println!("Filename:  `{}`", bv.metadata().filename());
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
                            .for_each(|token| print!("{}", token.text().to_str().unwrap()));
                        println!("")
                    }
                    _ => (),
                }
            }
        }
    }

    // Important!  You need to call shutdown or your script will hang forever
    binaryninja::headless::shutdown();
}
