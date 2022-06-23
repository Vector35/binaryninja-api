use crate::architecture::{Architecture, CoreArchitecture};
use crate::function::Function;
use crate::rc::{Ref, RefCountable};
use binaryninjacore_sys::{
    BNArchitecture, BNBasicBlock, BNFreeBasicBlock, BNFreeBasicBlockList,
    BNFreeMediumLevelILFunction, BNFunction, BNGetBasicBlockEnd, BNGetBasicBlockIndex,
    BNGetBasicBlockStart, BNGetMediumLevelILBasicBlockList, BNGetMediumLevelILByIndex,
    BNGetMediumLevelILIndexForInstruction, BNMediumLevelILFunction, BNMediumLevelILInstruction,
    BNMediumLevelILOperation, BNNewBasicBlockReference, BNNewMediumLevelILFunctionReference,
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

#[derive(Debug)]
pub struct MediumLevelILInstruction {
    operation: BNMediumLevelILOperation,
    source_function: *mut BNMediumLevelILFunction,
    source_operand: u32,
    size: usize,
    operands: [u64; 5],
    address: u64,
    expr_index: usize,
    instruction_index: usize,
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
