use binaryninja::architecture::Architecture;
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
        for basic_block in &func.basic_blocks() {
            // TODO : This is intended to be refactored to be more nice to work with soon(TM)
            for addr in basic_block.as_ref() {
                if let Some((_, tokens)) = func.arch().instruction_text(
                    bv.read_buffer(addr, func.arch().max_instr_len())
                        .unwrap()
                        .get_data(),
                    addr,
                ) {
                    let line = tokens
                        .iter()
                        .map(|token| token.to_string())
                        .collect::<String>();
                    println!("{addr}    {line}");
                }
            }
        }
    }
}
