use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use criterion::{criterion_group, criterion_main, Criterion};
use std::path::PathBuf;
use warp_ninja::function_guid;

// These are the target files present in OUT_DIR
// Add the files to fixtures/bin
static TARGET_FILES: [&str; 1] = ["atox.obj"];

pub fn guid_benchmark(c: &mut Criterion) {
    let session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    for file_name in TARGET_FILES {
        let path = out_dir.join(file_name);
        let view = session.load(&path).expect("Failed to load view");

        let functions: Vec<_> = view.functions().iter().map(|f| f.to_owned()).collect();
        // Bench all functions sequentially
        c.bench_function("guid all functions", |b| {
            b.iter(|| {
                for func in &functions {
                    let llil = func.lifted_il().unwrap();
                    function_guid(&func, &llil);
                }
            })
        });
    }
}

criterion_group!(benches, guid_benchmark);
criterion_main!(benches);
