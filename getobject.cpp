
#include "getobject.hpp"
#include "binaryview.hpp"
#include "function.hpp"
#include "basicblock.hpp"
#include "lowlevelil.hpp"
#include "mediumlevelil.hpp"
#include "highlevelil.hpp"
#include "settings.hpp"
#include "platform.hpp"
#include "architecture.hpp"
#include "type.hpp"

using namespace BinaryNinja;

BNBinaryView* GetView(Ref<BinaryView> view)
{
	return view->GetObject();
}

BNBinaryView* GetObject(Ref<BinaryView> view)
{
	return view ? view->GetObject() : nullptr;
}

BNFunction* GetFunction(Ref<Function> func)
{
	return func ? func->GetObject() : nullptr;
}

BNBasicBlock* GetBasicBlock(Ref<BasicBlock> block)
{
	return block ? block->GetObject() : nullptr;
}

BNFunction* GetObject(Ref<Function> obj)
{
	return obj ? obj->GetObject() : nullptr;
}

BNBasicBlock* GetObject(Ref<BasicBlock> obj)
{
	return obj ? obj->GetObject() : nullptr;
}

BNLowLevelILFunction* GetObject(Ref<LowLevelILFunction> obj)
{
	return obj ? obj->GetObject() : nullptr;
}


BNMediumLevelILFunction* GetObject(Ref<MediumLevelILFunction> obj)
{
	return obj ? obj->GetObject() : nullptr;
}


BNHighLevelILFunction* GetObject(Ref<HighLevelILFunction> obj)
{
	return obj ? obj->GetObject() : nullptr;
}

BNType* GetObject(Ref<Type> obj)
{
	return obj ? obj->GetObject() : nullptr;
}

BNArchitecture* GetObject(Architecture* obj)
{
	return obj ? obj->GetObject() : nullptr;
}

BNDisassemblySettings* GetObject(Ref<DisassemblySettings> obj)
{
	return obj ? obj->GetObject() : nullptr;
}

BNPlatform* GetObject(Ref<Platform> obj)
{
	return obj ? obj->GetObject() : nullptr;
}

BNPlatform* GetObject(Platform* obj)
{
	return obj ? obj->GetObject() : nullptr;
}




Ref<BinaryView> BinaryNinja::CreateNewView(BNBinaryView* view)
{
	return view ? new BinaryView(view) : nullptr;
}


Ref<Function> BinaryNinja::CreateNewFunction(BNFunction* func)
{
	return func ? new Function(func) : nullptr;
}


Ref<BasicBlock> BinaryNinja::CreateNewBasicBlock(BNBasicBlock* block)
{
	return block ? new BasicBlock(block) : nullptr;
}


Ref<LowLevelILFunction> BinaryNinja::CreateNewLowLevelILFunction(BNLowLevelILFunction* func)
{
	return func ? new LowLevelILFunction(func) : nullptr;
}


Ref<MediumLevelILFunction> BinaryNinja::CreateNewMediumLevelILFunction(BNMediumLevelILFunction* func)
{
	return func ? new MediumLevelILFunction(func) : nullptr;
}


Ref<HighLevelILFunction> BinaryNinja::CreateNewHighLevelILFunction(BNHighLevelILFunction* func)
{
	return func ? new HighLevelILFunction(func) : nullptr;
}


Ref<Type> BinaryNinja::CreateNewType(BNType* type)
{
	return type ? new Type(type) : nullptr;
}


Ref<Platform> BinaryNinja::CreateNewPlatform(BNPlatform* platform)
{
	return platform ? new Platform(platform) : nullptr;
}

Ref<Architecture> BinaryNinja::CreateNewCoreArchitecture(BNArchitecture* arch)
{
	return arch ? new CoreArchitecture(arch) : nullptr;
}