use binaryninja::binaryview::BinaryViewExt;
use binaryninja::headless::Session;
use binaryninja::types::Conf;
use criterion::{criterion_group, criterion_main, Criterion};
use std::path::PathBuf;
use warp_ninja::convert::from_bn_type;

pub fn type_conversion_benchmark(c: &mut Criterion) {
    let session = Session::new();
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    for entry in std::fs::read_dir(out_dir).expect("Failed to read OUT_DIR") {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();
        if path.is_file() {
            if let Some(bv) = session.load(path.to_str().unwrap()) {
                let functions = bv.functions();
                c.bench_function("type conversion all functions", |b| {
                    b.iter(|| {
                        for func in &functions {
                            from_bn_type(&bv, &func.function_type(), u8::MAX);
                        }
                    })
                });

                let types = bv.types();
                c.bench_function("type conversion all types", |b| {
                    b.iter(|| {
                        for ty in &types {
                            from_bn_type(&bv, &ty.type_object(), u8::MAX);
                        }
                    })
                });
            }
        }
    }
}

criterion_group!(benches, type_conversion_benchmark);
criterion_main!(benches);
