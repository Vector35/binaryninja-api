use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    function::Function,
    mlil::{MediumLevelILFunction, MediumLevelILInstruction, MediumLevelILOperation},
    rc::Ref,
    symbol::SymbolType,
    types::{DataVariable, Type, TypeClass, Variable},
};

use inkwell::{
    builder::Builder,
    context::Context,
    module::Module,
    passes::{PassManager, PassManagerBuilder},
    targets::{InitializationConfig, Target},
    types::{AnyTypeEnum, BasicMetadataTypeEnum, BasicTypeEnum},
    values::{
        AnyValue, AnyValueEnum, BasicMetadataValueEnum, BasicValue, BasicValueEnum, FunctionValue,
        GlobalValue, IntValue, PointerValue,
    },
    AddressSpace, IntPredicate, OptimizationLevel,
};

use std::{collections::BTreeMap, ops::Deref};

struct BinaryInfo {
    bv: Ref<BinaryView>,
    data_vars: Vec<DataVariable>,
    imports: Vec<Ref<Function>>,
}

struct MLILInfo<'ctx> {
    func: Ref<MediumLevelILFunction>,
    var_map: BTreeMap<u32, (Variable, PointerValue<'ctx>)>,
    data_vars: BTreeMap<u64, (DataVariable, GlobalValue<'ctx>)>,
    imports: BTreeMap<String, FunctionValue<'ctx>>,
}

struct LLIRInfo<'a, 'ctx> {
    context: &'ctx Context,
    module: &'a Module<'ctx>,
    builder: &'a Builder<'ctx>,
    func: Option<FunctionValue<'ctx>>,
    blocks: BTreeMap<u64, inkwell::basic_block::BasicBlock<'ctx>>,
}

struct LLIRLifter<'a, 'ctx> {
    binary: BinaryInfo,
    mlil: MLILInfo<'ctx>,
    llir: LLIRInfo<'a, 'ctx>,
}

impl<'a, 'ctx> LLIRLifter<'a, 'ctx> {
    pub fn new(
        bv: Ref<BinaryView>,
        context: &'ctx Context,
        module: &'a Module<'ctx>,
        builder: &'a Builder<'ctx>,
    ) -> Self {
        LLIRLifter {
            binary: BinaryInfo {
                bv: bv.clone(),
                data_vars: bv.data_variables().iter().map(|dv| dv.clone()).collect(),
                imports: bv
                    .functions()
                    .iter()
                    .filter(|f| f.symbol().sym_type() == SymbolType::ImportedFunction)
                    .map(|f| f.to_owned())
                    .collect(),
            },
            mlil: MLILInfo {
                func: bv
                    .functions()
                    .iter()
                    .find(|f| f.symbol().full_name().as_str() == "_main")
                    .expect("Failed to locate main")
                    .mlil()
                    .expect("Failed to lift main to MLIL"),
                var_map: Default::default(),
                data_vars: Default::default(),
                imports: Default::default(),
            },
            llir: LLIRInfo {
                context,
                module,
                builder,
                func: None,
                blocks: Default::default(),
            },
        }
    }

    pub fn create_named_function(
        &mut self,
        name: &str,
        func: Ref<MediumLevelILFunction>,
    ) -> FunctionValue<'ctx> {
        self.llir.module.add_function(
            name,
            match self
                .to_llir_type(func.return_type().unwrap().contents.deref())
                .unwrap()
            {
                AnyTypeEnum::ArrayType(arr) => arr.fn_type(
                    func.parameter_vars()
                        .iter()
                        .map(|param| {
                            let llir_type = self
                                .to_llir_type(func.variable_type(param).unwrap().contents.deref());
                            self.to_basic_metadata_type(&llir_type.unwrap())
                        })
                        .collect::<Vec<BasicMetadataTypeEnum>>()
                        .as_slice(),
                    false,
                ),
                AnyTypeEnum::FloatType(fl) => fl.fn_type(
                    func.parameter_vars()
                        .iter()
                        .map(|param| {
                            let llir_type = self
                                .to_llir_type(func.variable_type(param).unwrap().contents.deref());
                            self.to_basic_metadata_type(&llir_type.unwrap())
                        })
                        .collect::<Vec<BasicMetadataTypeEnum>>()
                        .as_slice(),
                    false,
                ),
                AnyTypeEnum::FunctionType(_) => panic!("Invalid function return type"),
                AnyTypeEnum::IntType(int) => int.fn_type(
                    func.parameter_vars()
                        .iter()
                        .map(|param| {
                            let llir_type = self
                                .to_llir_type(func.variable_type(param).unwrap().contents.deref());
                            self.to_basic_metadata_type(&llir_type.unwrap())
                        })
                        .collect::<Vec<BasicMetadataTypeEnum>>()
                        .as_slice(),
                    false,
                ),
                AnyTypeEnum::PointerType(ptr) => ptr.fn_type(
                    func.parameter_vars()
                        .iter()
                        .map(|param| {
                            let llir_type = self
                                .to_llir_type(func.variable_type(param).unwrap().contents.deref());
                            self.to_basic_metadata_type(&llir_type.unwrap())
                        })
                        .collect::<Vec<BasicMetadataTypeEnum>>()
                        .as_slice(),
                    false,
                ),
                AnyTypeEnum::StructType(str) => str.fn_type(
                    func.parameter_vars()
                        .iter()
                        .map(|param| {
                            let llir_type = self
                                .to_llir_type(func.variable_type(param).unwrap().contents.deref());
                            self.to_basic_metadata_type(&llir_type.unwrap())
                        })
                        .collect::<Vec<BasicMetadataTypeEnum>>()
                        .as_slice(),
                    false,
                ),
                AnyTypeEnum::VectorType(vec) => vec.fn_type(
                    func.parameter_vars()
                        .iter()
                        .map(|param| {
                            let llir_type = self
                                .to_llir_type(func.variable_type(param).unwrap().contents.deref());
                            self.to_basic_metadata_type(&llir_type.unwrap())
                        })
                        .collect::<Vec<BasicMetadataTypeEnum>>()
                        .as_slice(),
                    false,
                ),
                AnyTypeEnum::VoidType(vd) => vd.fn_type(
                    func.parameter_vars()
                        .iter()
                        .map(|param| {
                            let llir_type = self
                                .to_llir_type(func.variable_type(param).unwrap().contents.deref());
                            self.to_basic_metadata_type(&llir_type.unwrap())
                        })
                        .collect::<Vec<BasicMetadataTypeEnum>>()
                        .as_slice(),
                    false,
                ),
            },
            None,
        )
    }

    pub fn setup(&mut self) {
        self.llir.func = Some(self.create_named_function("main", self.mlil.func.clone()));

        self.mlil
            .func
            .basic_blocks()
            .unwrap()
            .iter()
            .for_each(|bb| {
                let llir_bb = self
                    .llir
                    .context
                    .append_basic_block(self.llir.func.unwrap(), bb.start().to_string().as_str());
                self.llir.blocks.insert(bb.start(), llir_bb);
            });
    }

    pub fn setup_param_vars(&mut self) {
        let param_vars = self.mlil.func.parameter_vars();
        if param_vars.is_empty() {
        } else {
            let bbs = self.mlil.func.basic_blocks().unwrap();
            let bb = bbs.iter().nth(0).unwrap();
            let llir_bb = self.llir.blocks.get(&bb.start()).unwrap();
            self.llir.builder.position_at_end(*llir_bb);

            std::iter::zip(param_vars, self.llir.func.unwrap().get_params()).for_each(
                |(pvar, llir_param)| {
                    let (var_name, var_type) = self.mlil.func.variable_name_and_type(&pvar);
                    let llir_type = self
                        .to_llir_type(var_type.unwrap().contents.as_ref())
                        .unwrap();
                    let llir_var = self
                        .llir
                        .builder
                        .build_alloca(self.to_basic_type(&llir_type), var_name.as_str());
                    self.llir.builder.build_store(llir_var, llir_param);
                    self.mlil.var_map.insert(pvar.index, (pvar, llir_var));
                },
            );
        }
    }

    pub fn to_basic_type(&mut self, any: &AnyTypeEnum<'ctx>) -> BasicTypeEnum<'ctx> {
        match any {
            AnyTypeEnum::ArrayType(arr) => BasicTypeEnum::ArrayType(*arr),
            AnyTypeEnum::FloatType(fl) => BasicTypeEnum::FloatType(*fl),
            AnyTypeEnum::FunctionType(_) => {
                panic!("Invalid basic type")
            }
            AnyTypeEnum::IntType(int) => BasicTypeEnum::IntType(*int),
            AnyTypeEnum::PointerType(ptr) => BasicTypeEnum::PointerType(*ptr),
            AnyTypeEnum::StructType(str) => BasicTypeEnum::StructType(*str),
            AnyTypeEnum::VectorType(vec) => BasicTypeEnum::VectorType(*vec),
            AnyTypeEnum::VoidType(_) => {
                panic!("Invalid basic type")
            }
        }
    }

    pub fn to_basic_value(&mut self, any: &AnyValueEnum<'ctx>) -> BasicValueEnum<'ctx> {
        match any {
            AnyValueEnum::ArrayValue(arr) => BasicValueEnum::ArrayValue(*arr),
            AnyValueEnum::FloatValue(fl) => BasicValueEnum::FloatValue(*fl),
            AnyValueEnum::FunctionValue(_) => panic!("Invalid basic value"),
            AnyValueEnum::IntValue(int) => BasicValueEnum::IntValue(*int),
            AnyValueEnum::PointerValue(ptr) => BasicValueEnum::PointerValue(*ptr),
            AnyValueEnum::StructValue(str) => BasicValueEnum::StructValue(*str),
            AnyValueEnum::VectorValue(vec) => BasicValueEnum::VectorValue(*vec),
            AnyValueEnum::PhiValue(_) => panic!("Invalid basic value"),
            AnyValueEnum::InstructionValue(_) => panic!("Invalid basic value"),
            AnyValueEnum::MetadataValue(_) => panic!("Invalid basic value"),
        }
    }

    pub fn to_basic_metadata_value(
        &mut self,
        any: &AnyValueEnum<'ctx>,
    ) -> BasicMetadataValueEnum<'ctx> {
        match any {
            AnyValueEnum::ArrayValue(arr) => BasicMetadataValueEnum::ArrayValue(*arr),
            AnyValueEnum::FloatValue(fl) => BasicMetadataValueEnum::FloatValue(*fl),
            AnyValueEnum::FunctionValue(_) => panic!("Invalid metadata value"),
            AnyValueEnum::IntValue(int) => BasicMetadataValueEnum::IntValue(*int),
            AnyValueEnum::PointerValue(ptr) => BasicMetadataValueEnum::PointerValue(*ptr),
            AnyValueEnum::StructValue(str) => BasicMetadataValueEnum::StructValue(*str),
            AnyValueEnum::VectorValue(vec) => BasicMetadataValueEnum::VectorValue(*vec),
            AnyValueEnum::PhiValue(_) => panic!("Invalid metadata value"),
            AnyValueEnum::InstructionValue(_) => panic!("Invalid metadata value"),
            AnyValueEnum::MetadataValue(md) => BasicMetadataValueEnum::MetadataValue(*md),
        }
    }

    pub fn to_basic_metadata_type(
        &mut self,
        any: &AnyTypeEnum<'ctx>,
    ) -> BasicMetadataTypeEnum<'ctx> {
        match any {
            AnyTypeEnum::ArrayType(arr) => BasicMetadataTypeEnum::ArrayType(*arr),
            AnyTypeEnum::FloatType(fl) => BasicMetadataTypeEnum::FloatType(*fl),
            AnyTypeEnum::FunctionType(_) => {
                panic!("Invalid parameter type")
            }
            AnyTypeEnum::IntType(int) => BasicMetadataTypeEnum::IntType(*int),
            AnyTypeEnum::PointerType(ptr) => BasicMetadataTypeEnum::PointerType(*ptr),
            AnyTypeEnum::StructType(str) => BasicMetadataTypeEnum::StructType(*str),
            AnyTypeEnum::VectorType(vec) => BasicMetadataTypeEnum::VectorType(*vec),
            AnyTypeEnum::VoidType(_) => {
                panic!("Invalid parameter type")
            }
        }
    }

    pub fn to_llir_type(&mut self, ty: &Type) -> Option<AnyTypeEnum<'ctx>> {
        match ty.type_class() {
            TypeClass::VoidTypeClass => Some(self.llir.context.void_type().into()),
            TypeClass::BoolTypeClass => Some(self.llir.context.bool_type().into()),
            TypeClass::IntegerTypeClass => Some(
                self.llir
                    .context
                    .custom_width_int_type((ty.width() * 8) as u32)
                    .into(),
            ),
            TypeClass::FloatTypeClass => Some(match ty.width() * 8 {
                16 => self.llir.context.f16_type().into(),
                32 => self.llir.context.f32_type().into(),
                64 => self.llir.context.f64_type().into(),
                128 => self.llir.context.f128_type().into(),
                _ => panic!("Float larger than 128 bits"),
            }),
            TypeClass::StructureTypeClass => Some(
                self.llir
                    .context
                    .struct_type(
                        ty.get_structure()
                            .unwrap()
                            .members()
                            .iter()
                            .map(
                                |s| match self.to_llir_type(s.type_.clone().deref()).unwrap() {
                                    AnyTypeEnum::ArrayType(arr) => BasicTypeEnum::ArrayType(arr),
                                    AnyTypeEnum::FloatType(fl) => BasicTypeEnum::FloatType(fl),
                                    AnyTypeEnum::FunctionType(_) => {
                                        panic!("Invalid structure member")
                                    }
                                    AnyTypeEnum::IntType(int) => BasicTypeEnum::IntType(int),
                                    AnyTypeEnum::PointerType(ptr) => {
                                        BasicTypeEnum::PointerType(ptr)
                                    }
                                    AnyTypeEnum::StructType(str) => BasicTypeEnum::StructType(str),
                                    AnyTypeEnum::VectorType(vec) => BasicTypeEnum::VectorType(vec),
                                    AnyTypeEnum::VoidType(_) => {
                                        panic!("Invalid structure member")
                                    }
                                },
                            )
                            .collect::<Vec<BasicTypeEnum>>()
                            .as_slice(),
                        ty.get_structure().unwrap().packed(),
                    )
                    .into(),
            ),
            TypeClass::EnumerationTypeClass => Some(
                self.llir
                    .context
                    .custom_width_int_type(ty.width() as u32 * 8)
                    .into(),
            ),
            TypeClass::PointerTypeClass => Some(
                match self
                    .to_llir_type(ty.target().unwrap().contents.clone().deref())
                    .unwrap()
                {
                    AnyTypeEnum::ArrayType(arr) => arr.ptr_type(AddressSpace::Generic).into(),
                    AnyTypeEnum::FloatType(fl) => fl.ptr_type(AddressSpace::Generic).into(),
                    AnyTypeEnum::FunctionType(fnc) => fnc.ptr_type(AddressSpace::Generic).into(),
                    AnyTypeEnum::IntType(int) => int.ptr_type(AddressSpace::Generic).into(),
                    AnyTypeEnum::PointerType(ptr) => ptr.ptr_type(AddressSpace::Generic).into(),
                    AnyTypeEnum::StructType(str) => str.ptr_type(AddressSpace::Generic).into(),
                    AnyTypeEnum::VectorType(vec) => vec.ptr_type(AddressSpace::Generic).into(),
                    AnyTypeEnum::VoidType(_) => self
                        .llir
                        .context
                        .custom_width_int_type(ty.width() as u32 * 8)
                        .ptr_type(AddressSpace::Generic)
                        .into(),
                },
            ),
            TypeClass::ArrayTypeClass => Some(
                match self
                    .to_llir_type(ty.element_type().unwrap().contents.clone().deref())
                    .unwrap()
                {
                    AnyTypeEnum::ArrayType(arr) => arr.array_type(ty.count() as u32).into(),
                    AnyTypeEnum::FloatType(fl) => fl.array_type(ty.count() as u32).into(),
                    AnyTypeEnum::FunctionType(_) => panic!("Invalid array element type"),
                    AnyTypeEnum::IntType(int) => int.array_type(ty.count() as u32).into(),
                    AnyTypeEnum::PointerType(ptr) => ptr.array_type(ty.count() as u32).into(),
                    AnyTypeEnum::StructType(str) => str.array_type(ty.count() as u32).into(),
                    AnyTypeEnum::VectorType(vec) => vec.array_type(ty.count() as u32).into(),
                    AnyTypeEnum::VoidType(_) => panic!("Invalid array element type"),
                },
            ),
            TypeClass::FunctionTypeClass | TypeClass::VarArgsTypeClass => Some(
                match self
                    .to_llir_type(ty.return_value().unwrap().contents.deref())
                    .unwrap()
                {
                    AnyTypeEnum::ArrayType(arr) => arr
                        .fn_type(
                            ty.parameters()
                                .iter()
                                .map(|param| {
                                    let llir_type =
                                        self.to_llir_type(param.t.contents.deref()).unwrap();
                                    self.to_basic_metadata_type(&llir_type)
                                })
                                .collect::<Vec<BasicMetadataTypeEnum>>()
                                .as_slice(),
                            ty.has_variable_arguments().contents,
                        )
                        .into(),
                    AnyTypeEnum::FloatType(fl) => fl
                        .fn_type(
                            ty.parameters()
                                .iter()
                                .map(|param| {
                                    let llir_type =
                                        self.to_llir_type(param.t.contents.deref()).unwrap();
                                    self.to_basic_metadata_type(&llir_type)
                                })
                                .collect::<Vec<BasicMetadataTypeEnum>>()
                                .as_slice(),
                            ty.has_variable_arguments().contents,
                        )
                        .into(),
                    AnyTypeEnum::FunctionType(_) => panic!("Invalid parameter type"),
                    AnyTypeEnum::IntType(int) => int
                        .fn_type(
                            ty.parameters()
                                .iter()
                                .map(|param| {
                                    let llir_type =
                                        self.to_llir_type(param.t.contents.deref()).unwrap();
                                    self.to_basic_metadata_type(&llir_type)
                                })
                                .collect::<Vec<BasicMetadataTypeEnum>>()
                                .as_slice(),
                            ty.has_variable_arguments().contents,
                        )
                        .into(),
                    AnyTypeEnum::PointerType(ptr) => ptr
                        .fn_type(
                            ty.parameters()
                                .iter()
                                .map(|param| {
                                    let llir_type =
                                        self.to_llir_type(param.t.contents.deref()).unwrap();
                                    self.to_basic_metadata_type(&llir_type)
                                })
                                .collect::<Vec<BasicMetadataTypeEnum>>()
                                .as_slice(),
                            ty.has_variable_arguments().contents,
                        )
                        .into(),
                    AnyTypeEnum::StructType(str) => str
                        .fn_type(
                            ty.parameters()
                                .iter()
                                .map(|param| {
                                    let llir_type =
                                        self.to_llir_type(param.t.contents.deref()).unwrap();
                                    self.to_basic_metadata_type(&llir_type)
                                })
                                .collect::<Vec<BasicMetadataTypeEnum>>()
                                .as_slice(),
                            ty.has_variable_arguments().contents,
                        )
                        .into(),
                    AnyTypeEnum::VectorType(vec) => vec
                        .fn_type(
                            ty.parameters()
                                .iter()
                                .map(|param| {
                                    let llir_type =
                                        self.to_llir_type(param.t.contents.deref()).unwrap();
                                    self.to_basic_metadata_type(&llir_type)
                                })
                                .collect::<Vec<BasicMetadataTypeEnum>>()
                                .as_slice(),
                            ty.has_variable_arguments().contents,
                        )
                        .into(),
                    AnyTypeEnum::VoidType(vd) => vd
                        .fn_type(
                            ty.parameters()
                                .iter()
                                .map(|param| {
                                    let llir_type =
                                        self.to_llir_type(param.t.contents.deref()).unwrap();
                                    self.to_basic_metadata_type(&llir_type)
                                })
                                .collect::<Vec<BasicMetadataTypeEnum>>()
                                .as_slice(),
                            ty.has_variable_arguments().contents,
                        )
                        .into(),
                },
            ),
            TypeClass::ValueTypeClass => panic!("ValueTypeClass unsupported"),
            TypeClass::NamedTypeReferenceClass => {
                self.to_llir_type(ty.target().unwrap().contents.deref())
            }
            TypeClass::WideCharTypeClass => panic!("WideCharTypeClass unsupported"),
        }
    }

    pub fn setup_data_vars(&mut self) {
        self.binary
            .data_vars
            .iter()
            // TODO: remove this filter and actually handle different types of dvars
            .filter(|dv| {
                dv.t.contents.type_class() == TypeClass::ArrayTypeClass
                    && self.binary.bv.symbol_by_address(dv.address).is_err()
            })
            .map(|dv| dv.clone())
            .collect::<Vec<DataVariable>>()
            .iter()
            .for_each(|dv| {
                let llir_ty = self.to_llir_type(dv.t.contents.as_ref()).unwrap();
                let gl = self.llir.module.add_global(
                    self.to_basic_type(&llir_ty),
                    None,
                    format!("BN_GLOBAL_{:#x}", dv.address).as_str(),
                );
                let mut buf = Vec::<u8>::new();
                (0..dv.t.contents.width()).for_each(|_| buf.push(0));
                self.binary.bv.read(buf.as_mut_slice(), dv.address);
                let u8_arr = self.llir.context.custom_width_int_type(8).const_array(
                    buf.iter()
                        .map(|v| self.llir.context.i8_type().const_int(*v as u64, false))
                        .collect::<Vec<IntValue>>()
                        .as_slice(),
                );
                gl.set_initializer(&u8_arr);
                self.mlil.data_vars.insert(dv.address, ((*dv).clone(), gl));
            });
    }

    pub fn setup_imports(&mut self) {
        self.binary.imports.clone().iter().for_each(|f| {
            let mlil = f.mlil().unwrap();
            let mut import_name = f.symbol().full_name().to_string();
            let _ = import_name.remove(0);
            let func = self.create_named_function(import_name.as_str(), mlil);
            self.mlil.imports.insert(import_name, func);
        })
    }

    pub fn lift(&mut self, instr: &MediumLevelILInstruction) -> Option<AnyValueEnum<'ctx>> {
        match instr.info() {
            MediumLevelILOperation::Unimplemented => {
                println!("UNIMPLEMENTED: {:#x?}", instr.operation);
                None
            }
            MediumLevelILOperation::Nop => None,
            MediumLevelILOperation::SetVar { dest, src } => {
                if self.mlil.var_map.contains_key(&dest.index) {
                    let var = self.mlil.var_map.get(&dest.index).unwrap().1;
                    if let Some(llir_src) = self.lift(&src) {
                        match llir_src {
                            AnyValueEnum::PointerValue(ptr) => {
                                Some(AnyValueEnum::InstructionValue(
                                    self.llir
                                        .builder
                                        .build_store(var, self.llir.builder.build_load(ptr, "")),
                                ))
                            }
                            _ => Some(AnyValueEnum::InstructionValue(
                                self.llir
                                    .builder
                                    .build_store(var, self.to_basic_value(&llir_src)),
                            )),
                        }
                    } else {
                        None
                    }
                } else {
                    let (var_name, var_type) = self.mlil.func.variable_name_and_type(&dest);
                    let llir_var_type = self.to_llir_type(var_type.unwrap().contents.as_ref());
                    let llir_var = self.llir.builder.build_alloca(
                        self.to_basic_type(&llir_var_type.unwrap()),
                        var_name.as_str(),
                    );
                    self.mlil.var_map.insert(dest.index, (dest, llir_var));

                    if let Some(llir_src) = self.lift(&src) {
                        match llir_src {
                            AnyValueEnum::PointerValue(ptr) => {
                                Some(AnyValueEnum::InstructionValue(
                                    self.llir.builder.build_store(
                                        llir_var,
                                        self.llir.builder.build_load(ptr, ""),
                                    ),
                                ))
                            }
                            _ => Some(AnyValueEnum::InstructionValue(
                                self.llir
                                    .builder
                                    .build_store(llir_var, self.to_basic_value(&llir_src)),
                            )),
                        }
                    } else {
                        None
                    }
                }
            }
            MediumLevelILOperation::Call { dest, params, .. } => {
                let llir_params = params
                    .iter()
                    .map(|p| self.lift(p))
                    .collect::<Vec<Option<AnyValueEnum>>>();
                if let Some(dst) = self.lift(&dest) {
                    match dst {
                        AnyValueEnum::ArrayValue(_) => None,
                        AnyValueEnum::IntValue(_) => None,
                        AnyValueEnum::FloatValue(_) => None,
                        AnyValueEnum::PhiValue(_) => None,
                        AnyValueEnum::FunctionValue(fnc) => Some(
                            self.llir
                                .builder
                                .build_call(
                                    fnc,
                                    llir_params
                                        .iter()
                                        .map(|p| self.to_basic_metadata_value(&p.unwrap()))
                                        .collect::<Vec<BasicMetadataValueEnum<'ctx>>>()
                                        .as_slice(),
                                    "",
                                )
                                .as_any_value_enum(),
                        ),
                        AnyValueEnum::PointerValue(_) => None,
                        AnyValueEnum::StructValue(_) => None,
                        AnyValueEnum::VectorValue(_) => None,
                        AnyValueEnum::InstructionValue(_) => None,
                        AnyValueEnum::MetadataValue(_) => None,
                    }
                } else {
                    None
                }
            }
            MediumLevelILOperation::Ret { src } => {
                if let Some(ret) = self.lift(&(src.first().unwrap())) {
                    match ret {
                        AnyValueEnum::PointerValue(ptr) => Some(AnyValueEnum::InstructionValue(
                            self.llir
                                .builder
                                .build_return(Some(&self.llir.builder.build_load(ptr, ""))),
                        )),
                        _ => Some(AnyValueEnum::InstructionValue(
                            self.llir
                                .builder
                                .build_return(Some(&self.to_basic_value(&ret))),
                        )),
                    }
                } else {
                    Some(AnyValueEnum::InstructionValue(
                        self.llir.builder.build_return(None),
                    ))
                }
            }
            MediumLevelILOperation::SetVarField { .. } => None,
            MediumLevelILOperation::SetVarSplit { .. } => None,
            MediumLevelILOperation::ConstPtr { constant } => {
                if let Some((_, gvar)) = self.mlil.data_vars.get(&constant) {
                    Some(
                        self.llir
                            .builder
                            .build_bitcast(
                                gvar.as_basic_value_enum(),
                                self.llir
                                    .context
                                    .custom_width_int_type(
                                        (instr
                                            .expr_type()
                                            .unwrap()
                                            .target()
                                            .unwrap()
                                            .contents
                                            .width()
                                            * 8) as u32,
                                    )
                                    .ptr_type(AddressSpace::Generic),
                                "",
                            )
                            .as_any_value_enum(),
                    )
                } else {
                    let mut key = self
                        .binary
                        .bv
                        .symbol_by_address(constant)
                        .unwrap()
                        .full_name()
                        .to_string();
                    key.remove(0);
                    Some(AnyValueEnum::FunctionValue(
                        *self.mlil.imports.get(key.as_str()).unwrap(),
                    ))
                }
            }
            MediumLevelILOperation::Var { src } => Some(
                self.llir
                    .builder
                    .build_load(self.mlil.var_map.get(&src.index).unwrap().1, "")
                    .as_any_value_enum(),
            ),
            MediumLevelILOperation::Const { constant } => Some(AnyValueEnum::IntValue(
                self.llir
                    .context
                    .custom_width_int_type((instr.size * 8) as u32)
                    .const_int(constant, false),
            )),
            MediumLevelILOperation::AddressOf { .. } => None,
            MediumLevelILOperation::Goto { dest } => {
                self.llir
                    .builder
                    .build_unconditional_branch(*self.llir.blocks.get(&dest).unwrap());
                None
            }
            MediumLevelILOperation::If {
                condition,
                true_dest,
                false_dest,
            } => {
                if let Some(cond) = self.lift(&condition) {
                    let (then_bb, else_bb) = (
                        self.llir.blocks.get(&true_dest).unwrap(),
                        self.llir.blocks.get(&false_dest).unwrap(),
                    );
                    Some(AnyValueEnum::InstructionValue(
                        self.llir.builder.build_conditional_branch(
                            cond.into_int_value(),
                            *then_bb,
                            *else_bb,
                        ),
                    ))
                } else {
                    None
                }
            }
            MediumLevelILOperation::CmpSge { left, right } => {
                if let (Some(lhs), Some(rhs)) = (self.lift(&left), self.lift(&right)) {
                    Some(AnyValueEnum::IntValue(self.llir.builder.build_int_compare(
                        IntPredicate::SGE,
                        lhs.into_int_value(),
                        rhs.into_int_value(),
                        "",
                    )))
                } else {
                    None
                }
            }
            MediumLevelILOperation::Add { left, right } => {
                if let (Some(lhs), Some(rhs)) = (self.lift(&left), self.lift(&right)) {
                    let resolve_arithmetic = |val: AnyValueEnum<'ctx>| match val {
                        AnyValueEnum::IntValue(_) => AnyValueEnum::IntValue(val.into_int_value()),
                        AnyValueEnum::PointerValue(ptr) => AnyValueEnum::IntValue(
                            self.llir.builder.build_load(ptr, "").into_int_value(),
                        ),
                        _ => {
                            panic!("Not an integer")
                        }
                    };

                    let (ilhs, irhs) = (resolve_arithmetic(lhs), resolve_arithmetic(rhs));
                    Some(AnyValueEnum::IntValue(self.llir.builder.build_int_add(
                        ilhs.into_int_value(),
                        irhs.into_int_value(),
                        "",
                    )))
                } else {
                    None
                }
            }
            MediumLevelILOperation::Zx { src } => {
                // TODO: look into this maybe...?
                if let Some(zx) = self.lift(&src) {
                    let llir_type = self
                        .llir
                        .context
                        .custom_width_int_type((instr.size * 8) as u32);
                    Some(AnyValueEnum::IntValue(
                        self.llir
                            .builder
                            .build_int_z_extend(zx.into_int_value(), llir_type, ""),
                    ))
                } else {
                    None
                }
            }
        }
    }

    pub fn verify(&mut self) -> bool {
        match self.llir.module.verify() {
            Ok(_) => {
                println!("=== Module verified ===");
                true
            }
            Err(err) => {
                println!("=== Module failed to be verified ===");
                print!("{}", err.to_string());
                false
            }
        }
    }

    pub fn optimize(&mut self) {
        let config = InitializationConfig::default();
        Target::initialize_native(&config).unwrap();

        let pass_manager_builder = PassManagerBuilder::create();
        pass_manager_builder.set_optimization_level(OptimizationLevel::Aggressive);

        let fpm = PassManager::create(());
        pass_manager_builder.populate_module_pass_manager(&fpm);

        fpm.run_on(&self.llir.module);
    }

    pub fn write_to_file(&mut self, path: &str) {
        print!("{}", self.llir.module.to_string());
        std::fs::write(path, self.llir.module.to_string()).unwrap();

        println!("=== Module written to \"{}\" ===", path);
    }

    pub fn lift_function(&mut self) {
        self.setup_imports();
        self.setup_data_vars();
        self.setup_param_vars();
        self.mlil
            .func
            .basic_blocks()
            .unwrap()
            .iter()
            .for_each(|bb| {
                let llir_bb = self.llir.blocks.get(&bb.start()).unwrap();
                self.llir.builder.position_at_end(*llir_bb);

                bb.iter().for_each(|instr| {
                    self.lift(&instr);
                });
            });
    }

    pub fn run(&mut self) {
        self.setup();
        self.lift_function();
        if self.verify() {
            self.optimize();
        }
    }
}

fn main() {
    binaryninja::headless::init();

    let lifttest_path = [env!("CARGO_MANIFEST_DIR"), "/src/test/lifttest.bndb"].join("");
    let lifttest = binaryninja::open_view(lifttest_path).unwrap();

    let lifttest_context = Context::create();
    let lifttest_module = lifttest_context.create_module("lifttest");
    let lifttest_builder = lifttest_context.create_builder();

    let mut lifttest_lifter = LLIRLifter::new(
        lifttest,
        &lifttest_context,
        &lifttest_module,
        &lifttest_builder,
    );
    lifttest_lifter.run();
    lifttest_lifter.write_to_file(
        [env!("CARGO_MANIFEST_DIR"), "/src/test/liftest.ll"]
            .join("")
            .as_str(),
    );

    // ======

    let lifttest2_path = [env!("CARGO_MANIFEST_DIR"), "/src/test/lifttest_2.bndb"].join("");
    let lifttest2 = binaryninja::open_view(lifttest2_path).unwrap();

    let lifttest2_context = Context::create();
    let lifttest2_module = lifttest2_context.create_module("lifttest");
    let lifttest2_builder = lifttest2_context.create_builder();

    let mut lifttest2_lifter = LLIRLifter::new(
        lifttest2,
        &lifttest2_context,
        &lifttest2_module,
        &lifttest2_builder,
    );
    lifttest2_lifter.run();
    lifttest2_lifter.write_to_file(
        [env!("CARGO_MANIFEST_DIR"), "/src/test/liftest_2.ll"]
            .join("")
            .as_str(),
    );

    binaryninja::headless::shutdown();
}
