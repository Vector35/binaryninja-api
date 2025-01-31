use std::path::PathBuf;
use tempdir::TempDir;
use warp_ninja::processor::WarpFileProcessor;

// These are the target files present in OUT_DIR
// Add the files to fixtures/bin
static BIN_TARGET_FILES: [&str; 9] = [
    "_ctype.obj",
    "_fptostr.obj",
    "_mbslen.obj",
    "_memicmp.obj",
    "_strnicm.obj",
    "_wctype.obj",
    "atof.obj",
    "atoldbl.obj",
    "atox.obj",
];

#[test]
fn test_processor() {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let _headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    let processor = WarpFileProcessor::new();

    // All files should process and not error.
    for file_name in BIN_TARGET_FILES {
        let path = out_dir.join(file_name);
        processor.process(path).unwrap();
    }

    // We should be able to process a warp file.
    let warp_path = out_dir.join("random.warp");
    processor.process(warp_path).unwrap();
}

#[test]
fn test_caching() {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let cache_dir = TempDir::new("tmp_cache").unwrap();
    let _headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    let processor = WarpFileProcessor::new().with_cache_path(cache_dir.path().to_path_buf());

    // Go through files, this should cache the databases.
    for file_name in BIN_TARGET_FILES {
        let path = out_dir.join(file_name);
        processor.process(path).unwrap();
    }

    // Verify the databases were saved to the cache.
    let mut cached_paths = Vec::new();
    for entry in std::fs::read_dir(cache_dir.path()).expect("Failed to read cache dir") {
        let entry = entry.expect("Failed to read cache dir entry");
        let path = entry.path();
        assert!(path.is_file());
        cached_paths.push(path);
    }
    assert_eq!(BIN_TARGET_FILES.len(), cached_paths.len());
}
