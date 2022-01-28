// Copyright (c) 2015-2022 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "binaryninjaapi.h"

using namespace BinaryNinja;


FunctionRecognizer::FunctionRecognizer() {}


bool FunctionRecognizer::RecognizeLowLevelILCallback(
    void* ctxt, BNBinaryView* data, BNFunction* func, BNLowLevelILFunction* il)
{
	FunctionRecognizer* recog = (FunctionRecognizer*)ctxt;
	Ref<BinaryView> dataObj = new BinaryView(BNNewViewReference(data));
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	Ref<LowLevelILFunction> ilObj = new LowLevelILFunction(BNNewLowLevelILFunctionReference(il));
	return recog->RecognizeLowLevelIL(dataObj, funcObj, ilObj);
}


bool FunctionRecognizer::RecognizeMediumLevelILCallback(
    void* ctxt, BNBinaryView* data, BNFunction* func, BNMediumLevelILFunction* il)
{
	FunctionRecognizer* recog = (FunctionRecognizer*)ctxt;
	Ref<BinaryView> dataObj = new BinaryView(BNNewViewReference(data));
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	Ref<MediumLevelILFunction> ilObj = new MediumLevelILFunction(BNNewMediumLevelILFunctionReference(il));
	return recog->RecognizeMediumLevelIL(dataObj, funcObj, ilObj);
}


void FunctionRecognizer::RegisterGlobalRecognizer(FunctionRecognizer* recog)
{
	BNFunctionRecognizer reg;
	reg.context = recog;
	reg.recognizeLowLevelIL = RecognizeLowLevelILCallback;
	reg.recognizeMediumLevelIL = RecognizeMediumLevelILCallback;
	BNRegisterGlobalFunctionRecognizer(&reg);
}


void FunctionRecognizer::RegisterArchitectureFunctionRecognizer(Architecture* arch, FunctionRecognizer* recog)
{
	BNFunctionRecognizer reg;
	reg.context = recog;
	reg.recognizeLowLevelIL = RecognizeLowLevelILCallback;
	reg.recognizeMediumLevelIL = RecognizeMediumLevelILCallback;
	BNRegisterArchitectureFunctionRecognizer(arch->GetObject(), &reg);
}


bool FunctionRecognizer::RecognizeLowLevelIL(BinaryView*, Function*, LowLevelILFunction*)
{
	return false;
}


bool FunctionRecognizer::RecognizeMediumLevelIL(BinaryView*, Function*, MediumLevelILFunction*)
{
	return false;
}
