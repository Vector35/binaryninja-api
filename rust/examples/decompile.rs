use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::disassembly::{DisassemblyOption, DisassemblySettings};
use binaryninja::function::Function;
use binaryninja::linear_view::LinearViewObject;

fn decompile_to_c(view: &BinaryView, func: &Function) {
    let settings = DisassemblySettings::new();
    settings.set_option(DisassemblyOption::ShowAddress, false);
    settings.set_option(DisassemblyOption::WaitForIL, true);
    settings.set_option(DisassemblyOption::IndentHLILBody, false);
    settings.set_option(DisassemblyOption::ShowCollapseIndicators, false);
    settings.set_option(DisassemblyOption::ShowFunctionHeader, false);

    let linear_view = LinearViewObject::language_representation(view, &settings, "Pseudo C");

    let mut cursor = linear_view.create_cursor();
    cursor.seek_to_address(func.highest_address());

    let last = view.get_next_linear_disassembly_lines(&mut cursor.duplicate());
    let first = view.get_previous_linear_disassembly_lines(&mut cursor);

    let lines = first.into_iter().chain(&last);

    for line in lines {
        println!("{}", line);
    }
}

pub fn main() {
    let filename = std::env::args().nth(1).expect("No filename provided");

    println!("Starting session...");
    // This loads all the core architecture, platform, etc plugins
    let headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    println!("Loading binary...");
    let bv = headless_session
        .load(&filename)
        .expect("Couldn't open file!");

    println!("Filename:  `{}`", bv.file().filename());
    println!("File size: `{:#x}`", bv.len());
    println!("Function count: {}", bv.functions().len());

    for func in &bv.functions() {
        decompile_to_c(bv.as_ref(), func.as_ref());
    }
}
