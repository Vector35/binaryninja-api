//! This tests to make sure the function GUIDs are stable.
use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use std::collections::BTreeMap;
use std::path::PathBuf;
use warp::signature::function::FunctionGUID;
use warp_ninja::cache::cached_function_guid;

// These are the target files present in OUT_DIR
// Add the files to fixtures/bin
static TARGET_FILES: [&str; 10] = [
    "_ctype.obj",
    "_fptostr.obj",
    "_mbslen.obj",
    "_memicmp.obj",
    "_strnicm.obj",
    "_wctype.obj",
    "atof.obj",
    "atoldbl.obj",
    "atox.obj",
    "ls",
];

#[test]
fn insta_signatures() {
    let session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    for file_name in TARGET_FILES {
        let path = out_dir.join(file_name);
        let view = session.load(&path).expect("Failed to load view");
        let functions: BTreeMap<u64, FunctionGUID> = view
            .functions()
            .iter()
            .map(|f| {
                let guid = cached_function_guid(&f, || f.lifted_il().ok());
                (f.start(), guid.unwrap())
            })
            .collect();
        insta::assert_debug_snapshot!(file_name, functions);
    }
}
