use crate::convert::to_bn_type;
use binaryninja::binaryview::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use std::time::Instant;

pub struct LoadTypes;

impl Command for LoadTypes {
    fn action(&self, view: &BinaryView) {
        let Some(file) = binaryninja::interaction::get_open_filename_input(
            "Apply Signature File Types",
            "*.sbin",
        ) else {
            return;
        };

        let Ok(data) = std::fs::read(&file) else {
            log::error!("Could not read signature file: {:?}", file);
            return;
        };

        let Some(data) = warp::signature::Data::from_bytes(&data) else {
            log::error!("Could not get data from signature file: {:?}", file);
            return;
        };

        let Some(arch) = view.default_arch() else {
            log::error!("Could not get default architecture");
            return;
        };

        let view = view.to_owned();
        std::thread::spawn(move || {
            let background_task = binaryninja::backgroundtask::BackgroundTask::new(
                format!("Applying {} types...", data.types.len()),
                true,
            )
            .unwrap();

            let start = Instant::now();
            for comp_ty in data.types {
                let ty_id = comp_ty.guid.to_string();
                let ty_name = comp_ty.ty.name.to_owned().unwrap_or_else(|| ty_id.clone());
                view.define_auto_type_with_id(ty_name, ty_id, &to_bn_type(&arch, &comp_ty.ty));
            }

            log::info!("Type application took {:?}", start.elapsed());
            background_task.finish();
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
