use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use criterion::{criterion_group, criterion_main, Criterion};
use warp_ninja::function_guid;

pub fn guid_benchmark(c: &mut Criterion) {
    let session = Session::new().expect("Failed to initialize session");
    let bv = session.load(env!("TEST_BIN_LIBRARY_OBJ")).unwrap();
    let functions = bv.functions();
    assert_eq!(functions.len(), 6);
    let mut function_iter = functions.into_iter();
    let first_function = function_iter.next().unwrap();

    c.bench_function("function guid", |b| {
        b.iter(|| {
            let llil = first_function.low_level_il().unwrap();
            function_guid(&first_function, &llil);
        })
    });
}

criterion_group!(benches, guid_benchmark);
criterion_main!(benches);
