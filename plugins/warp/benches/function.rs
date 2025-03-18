use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use criterion::{criterion_group, criterion_main, Criterion};
use rayon::prelude::*;
use warp_ninja::build_function;
use warp_ninja::cache::FunctionCache;

pub fn function_benchmark(c: &mut Criterion) {
    let session = Session::new().expect("Failed to initialize session");
    let bv = session.load(env!("TEST_BIN_LIBRARY_OBJ")).unwrap();
    let functions = bv.functions();
    assert_eq!(functions.len(), 6);
    let mut function_iter = functions.into_iter();
    let first_function = function_iter.next().unwrap();

    c.bench_function("signature first function", |b| {
        b.iter(|| {
            let _ = build_function(&first_function, &first_function.low_level_il().unwrap());
        })
    });

    c.bench_function("signature all functions", |b| {
        b.iter(|| {
            for func in &functions {
                let _ = build_function(&func, &func.low_level_il().unwrap());
            }
        })
    });

    let cache = FunctionCache::default();
    c.bench_function("signature all functions rayon", |b| {
        b.iter(|| {
            functions
                .par_iter()
                .map_with(cache.clone(), |par_cache, func| {
                    let llil = func.low_level_il().ok()?;
                    Some(par_cache.function(func.as_ref(), llil.as_ref()))
                })
                .collect::<Vec<_>>()
        })
    });
}

criterion_group!(benches, function_benchmark);
criterion_main!(benches);
