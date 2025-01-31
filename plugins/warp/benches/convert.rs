use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use criterion::{criterion_group, criterion_main, Criterion};
use std::path::PathBuf;
use warp_ninja::convert::from_bn_type;

// These are the target files present in OUT_DIR
// Add the files to fixtures/bin
static TARGET_FILES: [&str; 1] = ["atox.obj"];

pub fn type_conversion_benchmark(c: &mut Criterion) {
    let session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    for file_name in TARGET_FILES {
        let path = out_dir.join(file_name);
        let view = session.load(&path).expect("Failed to load view");

        // Bench function types.
        let functions: Vec<_> = view.functions().iter().map(|f| f.to_owned()).collect();
        c.bench_function("type conversion all functions", |b| {
            b.iter(|| {
                for func in &functions {
                    from_bn_type(&view, &func.function_type(), u8::MAX);
                }
            })
        });

        // Bench view types.
        let types = view.types().to_vec();
        c.bench_function("type conversion all types", |b| {
            b.iter(|| {
                for ty in &types {
                    from_bn_type(&view, &ty.ty, u8::MAX);
                }
            })
        });
    }
}

criterion_group!(benches, type_conversion_benchmark);
criterion_main!(benches);
