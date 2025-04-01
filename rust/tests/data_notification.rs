use std::path::PathBuf;

use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::data_notification::*;
use binaryninja::function::Function;
use binaryninja::headless::Session;
use binaryninja::tags::TagReference;

#[test]
fn test_data_notification_dyn_closure() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let bv = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");

    let mut func_updated_count = 0usize;
    let custom = DataNotificationClosure::default()
        .function_updated(|_bv: &BinaryView, _func: &Function| {
            func_updated_count += 1;
        })
        .register(&bv);

    let crash = bv.create_tag_type("Test", "🚧");
    let funcs = bv.functions();
    for func in &funcs {
        func.add_tag(
            &crash,
            "Dummy tag",
            Some(10.try_into().unwrap()),
            true,
            None,
        );
    }
    custom.unregister();

    // Verify that we no longer have the notification
    let funcs = bv.functions();
    for func in &funcs {
        func.add_tag(
            &crash,
            "Dummy tag",
            Some(10.try_into().unwrap()),
            true,
            None,
        );
    }

    assert_eq!(funcs.len(), func_updated_count);
}

#[test]
fn test_data_notification_impl() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let bv = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");

    #[derive(Default)]
    struct Tag {
        tags: usize,
    }

    impl CustomDataNotification for Tag {
        fn tag_added(&mut self, _view: &BinaryView, _tag_ref: &TagReference) {
            self.tags += 1;
        }
    }

    let triggers = DataNotificationTriggers::default().tag_added();
    let tags_lock = Tag::default().register(&bv, triggers);

    let funcs = bv.functions();
    for (i, func) in funcs.iter().enumerate() {
        let crash = bv.create_tag_type("Test", "🚧");
        func.add_tag(&crash, "Dummy tag", Some(i.try_into().unwrap()), true, None);
    }

    let tags = tags_lock.unregister();

    assert_eq!(funcs.len(), tags.tags);
}
