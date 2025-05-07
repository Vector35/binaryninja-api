use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::debuginfo::*;
use binaryninja::headless::Session;
use binaryninja::types::{MemberAccess, MemberScope, StructureBuilder, Type, TypeBuilder};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

static TEST_PARSER_ENABLED: AtomicBool = AtomicBool::new(true);

struct TestDebugInfoParser;

impl CustomDebugInfoParser for TestDebugInfoParser {
    fn is_valid(&self, _view: &BinaryView) -> bool {
        TEST_PARSER_ENABLED.load(Ordering::SeqCst)
    }

    fn parse_info(
        &self,
        debug_info: &mut DebugInfo,
        _view: &BinaryView,
        _debug_file: &BinaryView,
        _progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        let test_type = TypeBuilder::int(4, true).finalize();
        let test_struct = StructureBuilder::new()
            .append(
                &test_type,
                "myfield",
                MemberAccess::PublicAccess,
                MemberScope::NoScope,
            )
            .finalize();
        let new_type = TypeBuilder::structure(&test_struct).finalize();
        debug_info.add_type("test_dbg", &new_type, &[]);

        let func_type = Type::function(&test_type, vec![], true);

        let test_func = DebugFunctionInfo::new(
            None,
            None,
            Some("test_func".to_string()),
            Some(func_type),
            Some(0x3b440),
            None,
            vec![],
            vec![],
        );
        debug_info.add_function(&test_func);
        true
    }
}

#[test]
fn test_debug_info() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();

    // Register test parser
    DebugInfoParser::register("test", TestDebugInfoParser);

    // Make sure it exists.
    let _parser = DebugInfoParser::from_name("test").expect("Debug info test parser exists");

    {
        let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
        view.type_by_name("test_dbg")
            .expect("Debug info test type exists");

        let func = view
            .function_at(&view.default_platform().unwrap(), 0x3b440)
            .expect("Debug info test function exists");
        assert_eq!(func.symbol().raw_name().to_string_lossy(), "test_func");
        view.file().close();
    }

    // Disable the parser for other tests, so we don't introduce any unwanted behavior.
    TEST_PARSER_ENABLED.store(false, Ordering::SeqCst);
}
