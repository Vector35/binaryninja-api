use binaryninja::{
    architecture::CoreRegister,
    binary_view::{BinaryView, BinaryViewBase as _},
    confidence::Conf,
    function::Function,
    low_level_il::{
        expression::{
            ExpressionHandler as _, LowLevelILExpression, LowLevelILExpressionKind, ValueExpr,
        },
        function::{LowLevelILFunction, Mutable, SSA},
        instruction::{InstructionHandler as _, LowLevelILInstruction, LowLevelILInstructionKind},
        operation::{CallSsa, Operation},
        LowLevelILSSARegisterKind,
    },
    rc::Ref,
    types::{FunctionParameter, Type},
    variable::PossibleValueSet,
};
use bstr::ByteSlice as _;

use super::MessageSendType;
use crate::{activities::util, metadata::Selector, workflow::Confidence, Error};

fn named_type(bv: &BinaryView, name: &str) -> Option<Ref<Type>> {
    bv.type_by_name(name)
        .map(|t| Type::named_type_from_type(name, &t))
}

// j_ prefixes are for stub functions in the dyld shared cache.
const ALLOC_FUNCTIONS: &[&str] = &[
    "_objc_alloc_init",
    "_objc_alloc_initWithZone",
    "_objc_alloc",
    "_objc_allocWithZone",
    "_objc_opt_new",
    "j__objc_alloc_init",
    "j__objc_alloc_initWithZone",
    "j__objc_alloc",
    "j__objc_allocWithZone",
    "j__objc_opt_new",
];

/// Extract parameter expressions from a call, handling the SeparateParamListSsa wrapper.
fn call_param_exprs<'a>(
    call_op: &'a Operation<'a, Mutable, SSA, CallSsa>,
) -> Option<Vec<LowLevelILExpression<'a, Mutable, SSA, ValueExpr>>> {
    let LowLevelILExpressionKind::CallParamSsa(params) = &call_op.param_expr().kind() else {
        return None;
    };

    let param_exprs = params.param_exprs();
    Some(
        if let Some(LowLevelILExpressionKind::SeparateParamListSsa(inner)) =
            param_exprs.first().map(|e| e.kind())
        {
            inner.param_exprs()
        } else {
            param_exprs
        },
    )
}

/// Follow an SSA register back through register-to-register copies to find the
/// instruction that originally defined its value.
fn source_def_for_register<'a>(
    ssa: &'a LowLevelILFunction<Mutable, SSA>,
    reg: LowLevelILSSARegisterKind<CoreRegister>,
) -> Option<LowLevelILInstruction<'a, Mutable, SSA>> {
    let mut def = ssa.get_ssa_register_definition(reg)?;
    while let LowLevelILInstructionKind::SetRegSsa(set_reg) = def.kind() {
        let LowLevelILExpressionKind::RegSsa(src_reg) = set_reg.source_expr().kind() else {
            break;
        };
        def = ssa.get_ssa_register_definition(src_reg.source_reg())?;
    }
    Some(def)
}

/// For init-family selectors on a normal message send, try to determine the return type
/// by tracing the receiver register back to an alloc call and resolving the class.
fn return_type_for_init_receiver(
    bv: &BinaryView,
    func: &Function,
    ssa: &LowLevelILFunction<Mutable, SSA>,
    insn: &LowLevelILInstruction<Mutable, SSA>,
    selector: &Selector,
    message_send_type: MessageSendType,
) -> Option<Ref<Type>> {
    if message_send_type != MessageSendType::Normal || !selector.is_init_family() {
        return None;
    }

    let call_op = match insn.kind() {
        LowLevelILInstructionKind::CallSsa(op) | LowLevelILInstructionKind::TailCallSsa(op) => op,
        _ => return None,
    };

    let param_exprs = call_param_exprs(&call_op)?;
    let LowLevelILExpressionKind::RegSsa(receiver_reg) = param_exprs.first()?.kind() else {
        return None;
    };

    let def = source_def_for_register(ssa, receiver_reg.source_reg())?;
    let def_call_op = match def.kind() {
        LowLevelILInstructionKind::CallSsa(op) | LowLevelILInstructionKind::TailCallSsa(op) => op,
        _ => return None,
    };

    // Check if the defining call is to an alloc function.
    let target_values = def_call_op.target().possible_values();
    let call_target = match target_values {
        PossibleValueSet::ConstantValue { value }
        | PossibleValueSet::ConstantPointerValue { value }
        | PossibleValueSet::ImportedAddressValue { value } => value as u64,
        _ => return None,
    };

    let target_name = bv
        .symbol_by_address(call_target)?
        .raw_name()
        .to_string_lossy()
        .into_owned();
    if !ALLOC_FUNCTIONS.contains(&target_name.as_str()) {
        return None;
    }

    // Get the class from the alloc call's first parameter.
    let alloc_params = call_param_exprs(&def_call_op)?;
    let LowLevelILExpressionKind::RegSsa(class_reg) = alloc_params.first()?.kind() else {
        return None;
    };

    let class_addr = ssa.get_ssa_register_value(class_reg.source_reg())?.value as u64;
    if class_addr == 0 {
        return None;
    }

    let class_symbol_name = bv.symbol_by_address(class_addr)?.full_name();
    let class_name = util::class_name_from_symbol_name(class_symbol_name.to_bytes().as_bstr())?;
    let class_type = bv.type_by_name(class_name.to_str_lossy())?;
    Some(Type::pointer(&func.arch(), &class_type))
}

pub fn process_call(
    bv: &BinaryView,
    func: &Function,
    ssa: &LowLevelILFunction<Mutable, SSA>,
    insn: &LowLevelILInstruction<Mutable, SSA>,
    selector: &Selector,
    message_send_type: MessageSendType,
) -> Result<(), Error> {
    let arch = func.arch();
    let id = named_type(bv, "id").unwrap_or_else(|| Type::pointer(&arch, &Type::void()));
    let (receiver_type, receiver_name) = match message_send_type {
        MessageSendType::Normal => (id.clone(), "self"),
        MessageSendType::Super => (
            Type::pointer(
                &arch,
                &named_type(bv, "objc_super").unwrap_or_else(Type::void),
            ),
            "super",
        ),
    };
    let sel = named_type(bv, "SEL").unwrap_or_else(|| Type::pointer(&arch, &Type::char()));

    let return_type =
        return_type_for_init_receiver(bv, func, ssa, insn, selector, message_send_type)
            .unwrap_or_else(|| id.clone());

    let mut params = vec![
        FunctionParameter::new(receiver_type, receiver_name.to_string(), None),
        FunctionParameter::new(sel, "sel".to_string(), None),
    ];

    let argument_labels = selector.argument_labels();
    let mut argument_names = generate_argument_names(&argument_labels);

    // Pad out argument names if necessary
    for i in argument_names.len()..argument_labels.len() {
        argument_names.push(format!("arg{i}"));
    }

    // Create types for all arguments. For now they're all signed integers of the platform word size.
    let arg_type = Type::int(bv.address_size(), true);
    params.extend(
        argument_names
            .into_iter()
            .map(|name| FunctionParameter::new(arg_type.clone(), name, None)),
    );

    let func_type = Type::function(&return_type, params, false);
    func.set_auto_call_type_adjustment(
        insn.address(),
        Conf::new(func_type, Confidence::ObjCMsgSend as u8).as_ref(),
        Some(arch),
    );

    Ok(())
}

fn selector_label_without_prefix(prefix: &str, label: &str) -> Option<String> {
    if label.len() <= prefix.len() || !label.starts_with(prefix) {
        return None;
    }

    let after_prefix = &label[prefix.len()..];

    // If the character after the prefix is lowercase, the label may be something like "settings"
    // in which case "set" should not be considered a prefix.
    let (first, rest) = after_prefix.split_at_checked(1)?;
    if first.chars().next()?.is_lowercase() {
        return None;
    }

    // Lowercase the first character if the second character is not also uppercase.
    // This ensures we leave initialisms such as `URL` alone.
    let (second, rest) = rest.split_at_checked(1)?;
    Some(match second.chars().next() {
        Some(c) if c.is_lowercase() => {
            format!("{}{}{}", first.to_lowercase(), second, rest)
        }
        _ => after_prefix.to_string(),
    })
}

fn argument_name_from_selector_label(label: &str) -> String {
    // TODO: Handle other common patterns such as <do some action>With<arg>: and <do some action>For<arg>:
    let prefixes = [
        "initWith", "with", "and", "using", "set", "read", "to", "for",
    ];

    for prefix in prefixes {
        if let Some(arg_name) = selector_label_without_prefix(prefix, label) {
            return arg_name;
        }
    }

    label.to_owned()
}

fn generate_argument_names(labels: &[String]) -> Vec<String> {
    labels
        .iter()
        .map(|label| argument_name_from_selector_label(label))
        .collect()
}
