#pragma once

struct BNBinaryView;
struct BNFunction;
struct BNLowLevelILFunction;
struct BNMediumLevelILFunction;

namespace BinaryNinja {
	class Architecture;
	class BinaryView;
	class Function;
	class LowLevelILFunction;
	class MediumLevelILFunction;

	class FunctionRecognizer
	{
		static bool RecognizeLowLevelILCallback(
			void* ctxt, BNBinaryView* data, BNFunction* func, BNLowLevelILFunction* il);
		static bool RecognizeMediumLevelILCallback(
			void* ctxt, BNBinaryView* data, BNFunction* func, BNMediumLevelILFunction* il);

	  public:
		FunctionRecognizer();

		static void RegisterGlobalRecognizer(FunctionRecognizer* recog);
		static void RegisterArchitectureFunctionRecognizer(Architecture* arch, FunctionRecognizer* recog);

		virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il);
		virtual bool RecognizeMediumLevelIL(BinaryView* data, Function* func, MediumLevelILFunction* il);
	};
}