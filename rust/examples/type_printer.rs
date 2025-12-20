use binaryninja::tracing::TracingLogListener;
use binaryninja::types::printer::{CoreTypePrinter, TokenEscapingType};
use binaryninja::types::{MemberAccess, MemberScope, Structure, StructureMember, Type};

fn main() {
    tracing_subscriber::fmt::init();
    let _listener = TracingLogListener::new().register();

    // This loads all the core architecture, platform, etc plugins
    let headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    tracing::info!("Loading binary...");
    let bv = headless_session
        .load("/bin/cat")
        .expect("Couldn't open `/bin/cat`");

    let type_printer = CoreTypePrinter::default();
    let my_structure = Type::structure(
        &Structure::builder()
            .insert_member(
                StructureMember::new(
                    Type::int(4, false).into(),
                    "my_field".to_string(),
                    0,
                    MemberAccess::PublicAccess,
                    MemberScope::NoScope,
                ),
                false,
            )
            .finalize(),
    );

    let printed_types = type_printer.print_all_types(
        [("my_struct", my_structure)],
        &bv,
        4,
        TokenEscapingType::NoTokenEscapingType,
    );

    println!("{:?}", printed_types.unwrap());
}
