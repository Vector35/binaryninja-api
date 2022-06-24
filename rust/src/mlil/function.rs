use crate::architecture::{Architecture, CoreArchitecture};
use crate::function::Function;
use crate::rc::{Ref, RefCountable};
use crate::types::Variable;
use binaryninjacore_sys::{
    BNArchitecture, BNBasicBlock, BNFreeBasicBlock, BNFreeBasicBlockList,
    BNFreeMediumLevelILFunction, BNFunction, BNGetBasicBlockEnd, BNGetBasicBlockIndex,
    BNGetBasicBlockStart, BNGetMediumLevelILBasicBlockList, BNGetMediumLevelILByIndex,
    BNGetMediumLevelILIndexForInstruction, BNGetMediumLevelILInstructionForExpr,
    BNMediumLevelILFreeOperandList, BNMediumLevelILFunction, BNMediumLevelILGetOperandList,
    BNMediumLevelILInstruction, BNMediumLevelILOperation, BNNewBasicBlockReference,
    BNNewMediumLevelILFunctionReference,
};

pub struct MediumLevelILFunction {
    arch: CoreArchitecture,
    handle: *mut BNMediumLevelILFunction,
    source_func: Ref<Function>,
}

pub struct BasicBlock {
    handle: *mut BNBasicBlock,
    source_func: Ref<MediumLevelILFunction>,
}

pub enum MediumLevelILOperation {
    None,
    Call {
        output: Vec<Variable>,
        dest: MediumLevelILInstruction,
        params: Vec<MediumLevelILInstruction>,
    },
}

#[derive(Debug)]
pub struct MediumLevelILInstruction {
    pub operation: BNMediumLevelILOperation,
    pub source_function: *mut BNMediumLevelILFunction,
    pub source_operand: u32,
    pub size: usize,
    pub operands: [u64; 5],
    pub address: u64,
    pub expr_index: usize,
    pub instruction_index: usize,
}

impl MediumLevelILInstruction {
    pub fn new(
        instr: BNMediumLevelILInstruction,
        source_function: *mut BNMediumLevelILFunction,
        expr_index: usize,
        instruction_index: usize,
    ) -> Self {
        Self {
            operation: instr.operation,
            source_function,
            source_operand: instr.sourceOperand,
            size: instr.size,
            operands: instr.operands,
            address: instr.address,
            expr_index,
            instruction_index,
        }
    }

    pub fn from_expr(
        func: *mut BNMediumLevelILFunction,
        expr_index: usize,
        instr_index: Option<usize>,
    ) -> MediumLevelILInstruction {
        let inst = unsafe { BNGetMediumLevelILByIndex(func, expr_index) };
        let instr_index = if let Some(index) = instr_index {
            instr_index.unwrap()
        } else {
            unsafe { BNGetMediumLevelILInstructionForExpr(func, expr_index) }
        };

        MediumLevelILInstruction::new(inst, func, expr_index, instr_index)
    }

    fn get_var_list(&self, index: usize) -> Vec<Variable> {
        let mut size = 0usize;
        let op_list = unsafe {
            BNMediumLevelILGetOperandList(self.source_function, self.expr_index, index, &mut size)
        };

        let res = (0..size)
            .map(|i| {
                Variable::from_identifier(self.source_function, unsafe {
                    *(op_list.offset(i as isize))
                })
            })
            .collect();

        unsafe { BNMediumLevelILFreeOperandList(op_list) };

        res
    }

    fn get_expr_list(&self, index: usize) -> Vec<MediumLevelILInstruction> {
        let mut size = 0usize;
        let op_list = unsafe {
            BNMediumLevelILGetOperandList(self.source_function, self.expr_index, index, &mut size)
        };

        let res = (0..size)
            .map(|i| {
                MediumLevelILInstruction::from_expr(
                    self.source_function,
                    unsafe { (*(op_list.offset(i as isize))) as usize },
                    None,
                )
            })
            .collect();

        unsafe { BNMediumLevelILFreeOperandList(op_list) };

        res
    }

    fn get_expr(&self, index: usize) -> MediumLevelILInstruction {
        MediumLevelILInstruction::from_expr(
            self.source_function,
            self.operands[index] as usize,
            None,
        )
    }

    pub fn info(&self) -> MediumLevelILOperation {
        use binaryninjacore_sys::BNMediumLevelILOperation::*;

        match self.operation {
            MLIL_CALL => MediumLevelILOperation::Call {
                output: self.get_var_list(0),
                dest: self.get_expr(2),
                params: self.get_expr_list(3),
            },
            _ => MediumLevelILOperation::None,
        }
    }
}

impl BasicBlock {
    pub fn new(handle: *mut BNBasicBlock, source_func: Ref<MediumLevelILFunction>) -> Self {
        Self {
            handle,
            source_func,
        }
    }

    pub fn start(&self) -> u64 {
        unsafe { BNGetBasicBlockStart(self.handle) }
    }

    pub fn end(&self) -> u64 {
        unsafe { BNGetBasicBlockEnd(self.handle) }
    }

    pub fn index(&self) -> usize {
        unsafe { BNGetBasicBlockIndex(self.handle) }
    }

    pub fn iter(&self) -> BasicBlockIterator {
        let index = self.start();
        BasicBlockIterator {
            block: &self,
            index,
        }
    }
}

impl MediumLevelILFunction {
    pub(crate) unsafe fn new(
        arch: *mut BNArchitecture,
        handle: *mut BNMediumLevelILFunction,
        source_func: *mut BNFunction,
    ) -> Ref<MediumLevelILFunction> {
        Ref::new(MediumLevelILFunction {
            arch: CoreArchitecture::from_raw(arch),
            handle,
            source_func: Function::from_raw(source_func),
        })
    }

    pub fn basic_blocks(&self) -> Result<Vec<Ref<BasicBlock>>, ()> {
        let mut count = 0usize;
        let blocklist = unsafe { BNGetMediumLevelILBasicBlockList(self.handle, &mut count) };
        if blocklist.is_null() {
            Err(())
        } else {
            let blocks = (0isize..count as isize)
                .map(|i| unsafe {
                    Ref::new(BasicBlock::new(
                        BNNewBasicBlockReference((*blocklist).offset(i)),
                        self.to_owned(),
                    ))
                })
                .collect();

            unsafe {
                BNFreeBasicBlockList(blocklist, count);
            }

            Ok(blocks)
        }
    }

    pub fn raw_expr(&self, index: usize) -> BNMediumLevelILInstruction {
        unsafe { BNGetMediumLevelILByIndex(self.handle, index) }
    }

    pub fn index_for_instruction(&self, index: usize) -> usize {
        unsafe { BNGetMediumLevelILIndexForInstruction(self.handle, index) }
    }

    pub fn instruction(&self, index: usize) -> MediumLevelILInstruction {
        let expr = self.index_for_instruction(index);
        MediumLevelILInstruction::new(self.raw_expr(expr), self.handle, expr, index)
    }
}

pub struct BasicBlockIterator<'a> {
    block: &'a BasicBlock,
    index: u64,
}

impl<'a> Iterator for BasicBlockIterator<'a> {
    type Item = MediumLevelILInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index > self.block.end() {
            None
        } else {
            let res = Some(self.block.source_func.instruction(self.index as usize));
            self.index += 1;
            res
        }
    }
}

impl ToOwned for MediumLevelILFunction {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for MediumLevelILFunction {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            arch: handle.arch,
            handle: BNNewMediumLevelILFunctionReference(handle.handle),
            source_func: handle.source_func.clone(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeMediumLevelILFunction(handle.handle);
    }
}

impl ToOwned for BasicBlock {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for BasicBlock {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewBasicBlockReference(handle.handle),
            source_func: handle.source_func.clone(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeBasicBlock(handle.handle);
    }
}
