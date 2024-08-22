use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::disassembly::{DisassemblyOption, DisassemblySettings};
use binaryninja::function::Function;
use binaryninja::linearview::{LinearViewCursor, LinearViewObject};

use clap::Parser;

/// Use binaryninja to decompile to C.
#[derive(Parser, Debug)]
#[clap(version, long_about = None)]
struct Args {
    /// Path to the file to decompile
    filename: String,
}

fn decompile_to_c(view: &BinaryView, func: &Function) {
    let settings = DisassemblySettings::new();
    settings.set_option(DisassemblyOption::ShowAddress, false);
    settings.set_option(DisassemblyOption::WaitForIL, true);

    let linearview = LinearViewObject::language_representation(view, &settings, "Pseudo C");

    let mut cursor = LinearViewCursor::new(&linearview);
    cursor.seek_to_address(func.highest_address());

    let last = view.get_next_linear_disassembly_lines(&mut cursor.duplicate());
    let first = view.get_previous_linear_disassembly_lines(&mut cursor);

    let lines = first.into_iter().chain(&last);

    for line in lines {
        println!("{}", line.as_ref());
    }
}

fn main() {
    let args = Args::parse();

    eprintln!("Loading plugins...");
    binaryninja::headless::init();

    eprintln!("Loading binary...");
    let bv = binaryninja::load(args.filename).expect("Couldn't open file");

    eprintln!("Filename:  `{}`", bv.file().filename());
    eprintln!("File size: `{:#x}`", bv.len());
    eprintln!("Function count: {}", bv.functions().len());

    for func in &bv.functions() {
        decompile_to_c(bv.as_ref(), func.as_ref());
    }

    binaryninja::headless::shutdown();
}
