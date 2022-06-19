#pragma once
#include <string>
#include <vector>
#include "refcount.hpp"
#include "core/linearviewobject.h"

namespace BinaryNinja {
	class BinaryView;
	class DisassemblySettings;
	class LinearDisassemblyLine;
	class Function;

	struct LinearViewObjectIdentifier
	{
		std::string name;
		BNLinearViewObjectIdentifierType type;
		uint64_t start, end;

		LinearViewObjectIdentifier();
		LinearViewObjectIdentifier(const std::string& name);
		LinearViewObjectIdentifier(const std::string& name, uint64_t addr);
		LinearViewObjectIdentifier(const std::string& name, uint64_t start, uint64_t end);
		LinearViewObjectIdentifier(const LinearViewObjectIdentifier& other);
	};

	class LinearViewObject :
	    public CoreRefCountObject<BNLinearViewObject, BNNewLinearViewObjectReference, BNFreeLinearViewObject>
	{
	  public:
		LinearViewObject(BNLinearViewObject* obj);

		Ref<LinearViewObject> GetFirstChild();
		Ref<LinearViewObject> GetLastChild();
		Ref<LinearViewObject> GetPreviousChild(LinearViewObject* obj);
		Ref<LinearViewObject> GetNextChild(LinearViewObject* obj);

		Ref<LinearViewObject> GetChildForAddress(uint64_t addr);
		Ref<LinearViewObject> GetChildForIdentifier(const LinearViewObjectIdentifier& id);
		int CompareChildren(LinearViewObject* a, LinearViewObject* b);

		std::vector<LinearDisassemblyLine> GetLines(LinearViewObject* prev, LinearViewObject* next);

		uint64_t GetStart() const;
		uint64_t GetEnd() const;

		LinearViewObjectIdentifier GetIdentifier() const;

		uint64_t GetOrderingIndexTotal() const;
		uint64_t GetOrderingIndexForChild(LinearViewObject* obj) const;
		Ref<LinearViewObject> GetChildForOrderingIndex(uint64_t idx);

		static Ref<LinearViewObject> CreateDisassembly(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLiftedIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLowLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLowLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMediumLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMediumLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMappedMediumLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateMappedMediumLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateHighLevelIL(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateHighLevelILSSAForm(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateLanguageRepresentation(BinaryView* view, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateDataOnly(BinaryView* view, DisassemblySettings* settings);

		static Ref<LinearViewObject> CreateSingleFunctionDisassembly(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLiftedIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLowLevelIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLowLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMediumLevelIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMediumLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMappedMediumLevelIL(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionMappedMediumLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionHighLevelIL(Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionHighLevelILSSAForm(
		    Function* func, DisassemblySettings* settings);
		static Ref<LinearViewObject> CreateSingleFunctionLanguageRepresentation(
		    Function* func, DisassemblySettings* settings);
	};

	class LinearViewCursor :
	    public CoreRefCountObject<BNLinearViewCursor, BNNewLinearViewCursorReference, BNFreeLinearViewCursor>
	{
	  public:
		LinearViewCursor(LinearViewObject* root);
		LinearViewCursor(BNLinearViewCursor* cursor);

		bool IsBeforeBegin() const;
		bool IsAfterEnd() const;
		bool IsValid() const;

		Ref<LinearViewObject> GetCurrentObject() const;
		std::vector<LinearViewObjectIdentifier> GetPath() const;
		std::vector<Ref<LinearViewObject>> GetPathObjects() const;
		BNAddressRange GetOrderingIndex() const;
		uint64_t GetOrderingIndexTotal() const;

		void SeekToBegin();
		void SeekToEnd();
		void SeekToAddress(uint64_t addr);
		bool SeekToPath(const std::vector<LinearViewObjectIdentifier>& path);
		bool SeekToPath(const std::vector<LinearViewObjectIdentifier>& path, uint64_t addr);
		bool SeekToPath(LinearViewCursor* cursor);
		bool SeekToPath(LinearViewCursor* cursor, uint64_t addr);
		void SeekToOrderingIndex(uint64_t idx);
		bool Next();
		bool Previous();

		std::vector<LinearDisassemblyLine> GetLines();

		Ref<LinearViewCursor> Duplicate();

		static int Compare(LinearViewCursor* a, LinearViewCursor* b);
	};
}