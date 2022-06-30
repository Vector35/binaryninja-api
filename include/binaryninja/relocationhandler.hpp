#pragma once
#include "refcount.hpp"
#include "binaryninjacore/relocationhandler.h"

struct BNRelocationHandler;
struct BNBinaryView;
struct BNArchitecture;
struct BNRelocationInfo;

namespace BinaryNinja {

	class Relocation;
	class BinaryView;
	class Symbol;
	class LowLevelILFunction;
	class Architecture;

	class RelocationHandler :
		public CoreRefCountObject<BNRelocationHandler, BNNewRelocationHandlerReference, BNFreeRelocationHandler>
	{
		static bool GetRelocationInfoCallback(
			void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocationInfo* result, size_t resultCount);
		static bool ApplyRelocationCallback(
			void* ctxt, BNBinaryView* view, BNArchitecture* arch, BNRelocation* reloc, uint8_t* dest, size_t len);
		static size_t GetOperandForExternalRelocationCallback(void* ctxt, const uint8_t* data, uint64_t addr,
			size_t length, BNLowLevelILFunction* il, BNRelocation* relocation);

	  protected:
		RelocationHandler();
		RelocationHandler(BNRelocationHandler* handler);
		static void FreeCallback(void* ctxt);

	  public:
		virtual bool GetRelocationInfo(
			Ref<BinaryView> view, Ref<Architecture> arch, std::vector<BNRelocationInfo>& result);
		virtual bool ApplyRelocation(
			Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len);
		virtual size_t GetOperandForExternalRelocation(
			const uint8_t* data, uint64_t addr, size_t length, Ref<LowLevelILFunction> il, Ref<Relocation> relocation);
	};

	class CoreRelocationHandler : public RelocationHandler
	{
	  public:
		CoreRelocationHandler(BNRelocationHandler* handler);
		virtual bool GetRelocationInfo(
			Ref<BinaryView> view, Ref<Architecture> arch, std::vector<BNRelocationInfo>& result) override;
		virtual bool ApplyRelocation(
			Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override;
		virtual size_t GetOperandForExternalRelocation(const uint8_t* data, uint64_t addr, size_t length,
			Ref<LowLevelILFunction> il, Ref<Relocation> relocation) override;
	};


	class Relocation : public CoreRefCountObject<BNRelocation, BNNewRelocationReference, BNFreeRelocation>
	{
	  public:
		Relocation(BNRelocation* reloc);
		BNRelocationInfo GetInfo() const;
		Architecture* GetArchitecture() const;
		uint64_t GetTarget() const;
		uint64_t GetAddress() const;
		Ref<Symbol> GetSymbol() const;
	};
}