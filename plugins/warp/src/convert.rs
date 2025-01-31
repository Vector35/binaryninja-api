pub mod symbol;
pub mod types;

use binaryninja::function::Comment as BNComment;
use binaryninja::function::Function as BNFunction;
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
pub use symbol::*;
pub use types::*;
use warp::signature::comment::FunctionComment;
use warp::target::Target;

pub fn bn_comment_to_comment(func: &BNFunction, bn_comment: BNComment) -> FunctionComment {
    let offset = (bn_comment.addr as i64) - (func.start() as i64);
    FunctionComment {
        offset,
        text: bn_comment.comment,
    }
}

pub fn comment_to_bn_comment(func: &BNFunction, comment: FunctionComment) -> BNComment {
    BNComment {
        addr: comment
            .offset
            .checked_add_unsigned(func.start())
            .unwrap_or_default() as u64,
        comment: comment.text,
    }
}

pub fn platform_to_target(platform: &Platform) -> Target {
    let arch_name = platform.arch().name();
    let platform_name = platform.name();
    // We do not want to populate the platform if we are actually only the architecture.
    if arch_name == platform_name {
        Target {
            architecture: Some(arch_name),
            platform: None,
        }
    } else {
        Target {
            architecture: Some(arch_name),
            platform: Some(platform_name),
        }
    }
}

pub fn target_to_platform(target: Target) -> Option<Ref<Platform>> {
    // First try using the platform, then try using the arch.
    match Platform::by_name(&target.platform.unwrap()) {
        None => Platform::by_name(&target.architecture.unwrap()).map(|platform| platform),
        Some(platform) => Some(platform),
    }
}
