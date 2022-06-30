#pragma once

#include "refcount.hpp"
// Since some headers are so large and takes a while to compile
// and *most* files don't even need to access members they can instead
// include this file saving considerable compile time
struct BNBinaryView;
struct BNFunction;
struct BNBasicBlock;
struct BNLowLevelILFunction;
struct BNMediumLevelILFunction;
struct BNHighLevelILFunction;
struct BNDisassemblySettings;
struct BNPlatform;
struct BNArchitecture;
struct BNType;

namespace BinaryNinja {
	class BinaryView;
	class Function;
	class BasicBlock;
	class LowLevelILFunction;
	class MediumLevelILFunction;
	class HighLevelILFunction;
	class Type;
	class DisassemblySettings;
	class Platform;
	class Architecture;

	BNBinaryView* GetView(Ref<BinaryView> view);
	BNFunction* GetFunction(Ref<Function> view);
	BNBasicBlock* GetBasicBlock(Ref<BasicBlock> view);

	BNBinaryView* GetObject(Ref<BinaryView> obj);
	BNFunction* GetObject(Ref<Function> obj);
	BNBasicBlock* GetObject(Ref<BasicBlock> obj);
	BNLowLevelILFunction* GetObject(Ref<LowLevelILFunction> obj);
	BNMediumLevelILFunction* GetObject(Ref<MediumLevelILFunction> obj);
	BNHighLevelILFunction* GetObject(Ref<HighLevelILFunction> obj);
	BNDisassemblySettings* GetObject(Ref<DisassemblySettings> obj);
	BNType* GetObject(Ref<Type> obj);
	BNArchitecture* GetObject(Architecture* obj);
	BNPlatform* GetObject(Ref<Platform>* obj);
	BNPlatform* GetObject(Platform* obj);
	// template <typename T>
	// auto GetObject(T obj) { return reinterpret_cast<CoreRefCountObject<T, nullptr, nullptr>*>(*(void**)&obj)->m_object; }

	Ref<BinaryView> CreateNewReferencedView(BNBinaryView* view);
	Ref<Function> CreateNewReferencedFunction(BNFunction* view);
	Ref<BasicBlock> CreateNewReferencedBasicBlock(BNBasicBlock* view);
	Ref<LowLevelILFunction> CreateNewReferencedLowLevelILFunction(BNLowLevelILFunction* func);
	Ref<MediumLevelILFunction> CreateNewReferencedMediumLevelILFunction(BNMediumLevelILFunction* func);
	Ref<HighLevelILFunction> CreateNewReferencedHighLevelILFunction(BNHighLevelILFunction* func);
	Ref<Type> CreateNewReferencedType(BNType* func);

	Ref<BinaryView> CreateNewView(BNBinaryView* view);
	Ref<Function> CreateNewFunction(BNFunction* view);
	Ref<BasicBlock> CreateNewBasicBlock(BNBasicBlock* view);
	Ref<LowLevelILFunction> CreateNewLowLevelILFunction(BNLowLevelILFunction* func);
	Ref<MediumLevelILFunction> CreateNewMediumLevelILFunction(BNMediumLevelILFunction* func);
	Ref<HighLevelILFunction> CreateNewHighLevelILFunction(BNHighLevelILFunction* func);
	Ref<Type> CreateNewType(BNType* func);
	Ref<Platform> CreateNewPlatform(BNPlatform* platform);
	Ref<Architecture> CreateNewCoreArchitecture(BNArchitecture* architecture);
}