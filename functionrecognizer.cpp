#include "binaryninjaapi.h"

using namespace BinaryNinja;


FunctionRecognizer::FunctionRecognizer()
{
}


bool FunctionRecognizer::RecognizeLowLevelILCallback(void* ctxt, BNBinaryView* data, BNFunction* func, BNLowLevelILFunction* il)
{
	FunctionRecognizer* recog = (FunctionRecognizer*)ctxt;
	Ref<BinaryView> dataObj = new BinaryView(BNNewViewReference(data));
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	Ref<LowLevelILFunction> ilObj = new LowLevelILFunction(BNNewLowLevelILFunctionReference(il));
	return recog->RecognizeLowLevelIL(dataObj, funcObj, ilObj);
}


void FunctionRecognizer::RegisterGlobalRecognizer(FunctionRecognizer* recog)
{
	BNFunctionRecognizer reg;
	reg.context = recog;
	reg.recognizeLowLevelIL = RecognizeLowLevelILCallback;
	BNRegisterGlobalFunctionRecognizer(&reg);
}


void FunctionRecognizer::RegisterArchitectureFunctionRecognizer(Architecture* arch, FunctionRecognizer* recog)
{
	BNFunctionRecognizer reg;
	reg.context = recog;
	reg.recognizeLowLevelIL = RecognizeLowLevelILCallback;
	BNRegisterArchitectureFunctionRecognizer(arch->GetArchitectureObject(), &reg);
}


bool FunctionRecognizer::RecognizeLowLevelIL(BinaryView*, Function*, LowLevelILFunction*)
{
	return false;
}
