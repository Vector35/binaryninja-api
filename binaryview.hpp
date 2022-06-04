#pragma once
#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>

#include "binaryview.h"
#include "json/json.h"

#include "refcount.hpp"
#include "tag.hpp"
#include "qualifiedname.hpp"
#include "analysis.hpp"
#include "databuffer.hpp"
#include "confidence.hpp"

namespace BinaryNinja
{
	class AnalysisCompletionEvent;
	class BackgroundTask;
	class BasicBlock;
	class BinaryDataNotification;
	class DisassemblySettings;
	class FileAccessor;
	class FileMetadata;
	class FlowGraph;
	class LinearDisassemblyLine;
	class Logger;
	class Metadata;
	class NameSpace;
	class Platform;
	class QualifiedName;
	class Relocation;
	class SaveSettings;
	class Section;
	class Segment;
	class Settings;
	class Structure;
	class Symbol;
	class Tag;
	class TagReference;
	class TagType;
	class Type;
	class TypeReferenceSource;
	class UndoAction;
	class UndoEntry;
	class User;
	class Workflow;
	struct PossibleValueSet;
	struct ReferenceSource;
	struct TypeParserResult;

	struct TypeReferenceSource
	{
		QualifiedName name;
		uint64_t offset;
		BNTypeReferenceType type;
	};


	struct DataVariable
	{
		DataVariable() {}
		DataVariable(uint64_t a, Type* t, bool d) : address(a), type(t), autoDiscovered(d) {}

		uint64_t address;
		Confidence<Ref<Type>> type;
		bool autoDiscovered;
	};

	struct DataVariableAndName
	{
		DataVariableAndName() {}
		DataVariableAndName(uint64_t a, Type* t, bool d, const std::string& n) :
		    address(a), type(t), autoDiscovered(d), name(n)
		{}

		uint64_t address;
		Confidence<Ref<Type>> type;
		bool autoDiscovered;
		std::string name;
	};

	struct TypeFieldReference
	{
		Ref<Function> func;
		Ref<Architecture> arch;
		uint64_t addr;
		size_t size;
		Confidence<Ref<Type>> incomingType;
	};


	class Segment : public CoreRefCountObject<BNSegment, BNNewSegmentReference, BNFreeSegment>
	{
	  public:
		Segment(BNSegment* seg);
		uint64_t GetStart() const;
		uint64_t GetLength() const;
		uint64_t GetEnd() const;
		uint64_t GetDataEnd() const;
		uint64_t GetDataOffset() const;
		uint64_t GetDataLength() const;
		uint32_t GetFlags() const;
		bool IsAutoDefined() const;

		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRanges() const;
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRangesAtAddress(uint64_t addr) const;
		std::vector<Ref<Relocation>> GetRelocationsInRange(uint64_t addr, uint64_t size) const;
		uint64_t GetRelocationsCount() const;

		void SetStart(uint64_t newSegmentBase);
		void SetLength(uint64_t length);
		void SetDataOffset(uint64_t dataOffset);
		void SetDataLength(uint64_t dataLength);
		void SetFlags(uint32_t flags);
	};

	class Section : public CoreRefCountObject<BNSection, BNNewSectionReference, BNFreeSection>
	{
	  public:
		Section(BNSection* sec);
		Section(const std::string& name, uint64_t start, uint64_t length, BNSectionSemantics semantics,
		    const std::string& type, uint64_t align, uint64_t entrySize, const std::string& linkedSection,
		    const std::string& infoSection, uint64_t infoData, bool autoDefined);
		std::string GetName() const;
		std::string GetType() const;
		uint64_t GetStart() const;
		uint64_t GetLength() const;
		uint64_t GetInfoData() const;
		uint64_t GetAlignment() const;
		uint64_t GetEntrySize() const;
		std::string GetLinkedSection() const;
		std::string GetInfoSection() const;
		BNSectionSemantics GetSemantics() const;
		bool AutoDefined() const;
	};

	class BinaryDataNotification
	{
	  private:
		BNBinaryDataNotification m_callbacks;

		static void DataWrittenCallback(void* ctxt, BNBinaryView* data, uint64_t offset, size_t len);
		static void DataInsertedCallback(void* ctxt, BNBinaryView* data, uint64_t offset, size_t len);
		static void DataRemovedCallback(void* ctxt, BNBinaryView* data, uint64_t offset, uint64_t len);
		static void FunctionAddedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void FunctionRemovedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void FunctionUpdatedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void FunctionUpdateRequestedCallback(void* ctxt, BNBinaryView* data, BNFunction* func);
		static void DataVariableAddedCallback(void* ctxt, BNBinaryView* data, BNDataVariable* var);
		static void DataVariableRemovedCallback(void* ctxt, BNBinaryView* data, BNDataVariable* var);
		static void DataVariableUpdatedCallback(void* ctxt, BNBinaryView* data, BNDataVariable* var);
		static void SymbolAddedCallback(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		static void SymbolUpdatedCallback(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		static void SymbolRemovedCallback(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		static void DataMetadataUpdatedCallback(void* ctxt, BNBinaryView* object, uint64_t offset);
		static void TagTypeUpdatedCallback(void* ctxt, BNBinaryView* object, BNTagType* tagType);
		static void TagAddedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);
		static void TagUpdatedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);
		static void TagRemovedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);
		static void StringFoundCallback(void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);
		static void StringRemovedCallback(
		    void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);
		static void TypeDefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeUndefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeReferenceChangedCallback(void* ctx, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeFieldReferenceChangedCallback(
		    void* ctx, BNBinaryView* data, BNQualifiedName* name, uint64_t offset);

	  public:
		BinaryDataNotification();
		virtual ~BinaryDataNotification();

		BNBinaryDataNotification* GetCallbacks();

		virtual void OnBinaryDataWritten(BinaryView* view, uint64_t offset, size_t len);
		virtual void OnBinaryDataInserted(BinaryView* view, uint64_t offset, size_t len);
		virtual void OnBinaryDataRemoved(BinaryView* view, uint64_t offset, uint64_t len);
		virtual void OnAnalysisFunctionAdded(BinaryView* view, Function* func);
		virtual void OnAnalysisFunctionRemoved(BinaryView* view, Function* func);
		virtual void OnAnalysisFunctionUpdated(BinaryView* view, Function* func);
		virtual void OnAnalysisFunctionUpdateRequested(BinaryView* view, Function* func);
		virtual void OnDataVariableAdded(BinaryView* view, const DataVariable& var);
		virtual void OnDataVariableRemoved(BinaryView* view, const DataVariable& var);
		virtual void OnDataVariableUpdated(BinaryView* view, const DataVariable& var);
		virtual void OnDataMetadataUpdated(BinaryView* view, uint64_t offset);
		virtual void OnTagTypeUpdated(BinaryView* view, Ref<TagType> tagTypeRef);
		virtual void OnTagAdded(BinaryView* view, const TagReference& tagRef);
		virtual void OnTagUpdated(BinaryView* view, const TagReference& tagRef);
		virtual void OnTagRemoved(BinaryView* view, const TagReference& tagRef);
		virtual void OnSymbolAdded(BinaryView* view, Symbol* sym);
		virtual void OnSymbolUpdated(BinaryView* view, Symbol* sym);
		virtual void OnSymbolRemoved(BinaryView* view, Symbol* sym);
		virtual void OnStringFound(BinaryView* data, BNStringType type, uint64_t offset, size_t len);
		virtual void OnStringRemoved(BinaryView* data, BNStringType type, uint64_t offset, size_t len);
		virtual void OnTypeDefined(BinaryView* data, const QualifiedName& name, Type* type);
		virtual void OnTypeUndefined(BinaryView* data, const QualifiedName& name, Type* type);
		virtual void OnTypeReferenceChanged(BinaryView* data, const QualifiedName& name, Type* type);
		virtual void OnTypeFieldReferenceChanged(BinaryView* data, const QualifiedName& name, uint64_t offset);
	};

	/*! BinaryView is the base class for creating views on binary data (e.g. ELF, PE, Mach-O).
		BinaryView should be subclassed to create a new BinaryView
	*/
	class BinaryView : public CoreRefCountObject<BNBinaryView, BNNewViewReference, BNFreeBinaryView>
	{
	  protected:
		Ref<FileMetadata> m_file;  //!< The underlying file

		/*! BinaryView constructor
		   \param typeName name of the BinaryView (e.g. ELF, PE, Mach-O, ...)
		   \param file a file to create a view from
		   \param parentView optional view that contains the raw data used by this view
		 */
		BinaryView(const std::string& typeName, FileMetadata* file, BinaryView* parentView = nullptr);

		/*! PerformRead provides a mapping between the flat file and virtual offsets in the file.

			\param dest the address to write len number of bytes.
			\param offset the virtual offset to find and read len bytes from
			\param len the number of bytes to read from offset and write to dest
		*/
		virtual size_t PerformRead(void* dest, uint64_t offset, size_t len)
		{
			(void)dest;
			(void)offset;
			(void)len;
			return 0;
		}
		virtual size_t PerformWrite(uint64_t offset, const void* data, size_t len)
		{
			(void)offset;
			(void)data;
			(void)len;
			return 0;
		}
		virtual size_t PerformInsert(uint64_t offset, const void* data, size_t len)
		{
			(void)offset;
			(void)data;
			(void)len;
			return 0;
		}
		virtual size_t PerformRemove(uint64_t offset, uint64_t len)
		{
			(void)offset;
			(void)len;
			return 0;
		}

		virtual BNModificationStatus PerformGetModification(uint64_t offset)
		{
			(void)offset;
			return Original;
		}
		virtual bool PerformIsValidOffset(uint64_t offset);
		virtual bool PerformIsOffsetReadable(uint64_t offset);
		virtual bool PerformIsOffsetWritable(uint64_t offset);
		virtual bool PerformIsOffsetExecutable(uint64_t offset);
		virtual bool PerformIsOffsetBackedByFile(uint64_t offset);
		virtual uint64_t PerformGetNextValidOffset(uint64_t offset);
		virtual uint64_t PerformGetStart() const { return 0; }
		virtual uint64_t PerformGetLength() const { return 0; }
		virtual uint64_t PerformGetEntryPoint() const { return 0; }
		virtual bool PerformIsExecutable() const { return false; }
		virtual BNEndianness PerformGetDefaultEndianness() const;
		virtual bool PerformIsRelocatable() const;
		virtual size_t PerformGetAddressSize() const;

		virtual bool PerformSave(FileAccessor* file);
		void PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc);
		void PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> sym, uint64_t reloc);
		void NotifyDataWritten(uint64_t offset, size_t len);
		void NotifyDataInserted(uint64_t offset, size_t len);
		void NotifyDataRemoved(uint64_t offset, uint64_t len);

	  private:
		static bool InitCallback(void* ctxt);
		static void FreeCallback(void* ctxt);
		static size_t ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len);
		static size_t WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len);
		static size_t InsertCallback(void* ctxt, uint64_t offset, const void* src, size_t len);
		static size_t RemoveCallback(void* ctxt, uint64_t offset, uint64_t len);
		static BNModificationStatus GetModificationCallback(void* ctxt, uint64_t offset);
		static bool IsValidOffsetCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetReadableCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetWritableCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetExecutableCallback(void* ctxt, uint64_t offset);
		static bool IsOffsetBackedByFileCallback(void* ctxt, uint64_t offset);
		static uint64_t GetNextValidOffsetCallback(void* ctxt, uint64_t offset);
		static uint64_t GetStartCallback(void* ctxt);
		static uint64_t GetLengthCallback(void* ctxt);
		static uint64_t GetEntryPointCallback(void* ctxt);
		static bool IsExecutableCallback(void* ctxt);
		static BNEndianness GetDefaultEndiannessCallback(void* ctxt);
		static bool IsRelocatableCallback(void* ctxt);
		static size_t GetAddressSizeCallback(void* ctxt);
		static bool SaveCallback(void* ctxt, BNFileAccessor* file);

	  public:
		BinaryView(BNBinaryView* view);

		virtual bool Init();

		FileMetadata* GetFile() const;
		Ref<BinaryView> GetParentView() const;
		std::string GetTypeName() const;

		bool IsModified() const;
		bool IsAnalysisChanged() const;
		bool CreateDatabase(const std::string& path, Ref<SaveSettings> settings = nullptr);
		bool CreateDatabase(const std::string& path,
			const std::function<bool(size_t progress, size_t total)>& progressCallback,
			Ref<SaveSettings> settings = nullptr);
		bool SaveAutoSnapshot(Ref<SaveSettings> settings = nullptr);
		bool SaveAutoSnapshot(const std::function<bool(size_t progress, size_t total)>& progressCallback,
			Ref<SaveSettings> settings = nullptr);

		void BeginUndoActions();
		void AddUndoAction(UndoAction* action);
		void CommitUndoActions();

		bool Undo();
		bool Redo();

		std::string GetCurrentView();
		uint64_t GetCurrentOffset();
		bool Navigate(const std::string& view, uint64_t offset);

		size_t Read(void* dest, uint64_t offset, size_t len);
		DataBuffer ReadBuffer(uint64_t offset, size_t len);

		size_t Write(uint64_t offset, const void* data, size_t len);
		size_t WriteBuffer(uint64_t offset, const DataBuffer& data);

		size_t Insert(uint64_t offset, const void* data, size_t len);
		size_t InsertBuffer(uint64_t offset, const DataBuffer& data);

		size_t Remove(uint64_t offset, uint64_t len);

		std::vector<float> GetEntropy(uint64_t offset, size_t len, size_t blockSize);

		BNModificationStatus GetModification(uint64_t offset);
		std::vector<BNModificationStatus> GetModification(uint64_t offset, size_t len);

		bool IsValidOffset(uint64_t offset) const;
		bool IsOffsetReadable(uint64_t offset) const;
		bool IsOffsetWritable(uint64_t offset) const;
		bool IsOffsetExecutable(uint64_t offset) const;
		bool IsOffsetBackedByFile(uint64_t offset) const;
		bool IsOffsetCodeSemantics(uint64_t offset) const;
		bool IsOffsetWritableSemantics(uint64_t offset) const;
		bool IsOffsetExternSemantics(uint64_t offset) const;
		uint64_t GetNextValidOffset(uint64_t offset) const;

		uint64_t GetStart() const;
		uint64_t GetEnd() const;
		uint64_t GetLength() const;
		uint64_t GetEntryPoint() const;

		Ref<Architecture> GetDefaultArchitecture() const;
		void SetDefaultArchitecture(Architecture* arch);
		Ref<Platform> GetDefaultPlatform() const;
		void SetDefaultPlatform(Platform* platform);

		BNEndianness GetDefaultEndianness() const;
		bool IsRelocatable() const;
		size_t GetAddressSize() const;

		bool IsExecutable() const;

		bool Save(FileAccessor* file);
		bool Save(const std::string& path);

		void DefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc);
		void DefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> target, uint64_t reloc);
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRanges() const;
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRangesAtAddress(uint64_t addr) const;
		bool RangeContainsRelocation(uint64_t addr, size_t size) const;

		void RegisterNotification(BinaryDataNotification* notify);
		void UnregisterNotification(BinaryDataNotification* notify);

		void AddAnalysisOption(const std::string& name);
		void AddFunctionForAnalysis(Platform* platform, uint64_t addr);
		void AddEntryPointForAnalysis(Platform* platform, uint64_t start);
		void RemoveAnalysisFunction(Function* func);
		void CreateUserFunction(Platform* platform, uint64_t start);
		void RemoveUserFunction(Function* func);
		bool HasInitialAnalysis();
		void SetAnalysisHold(bool enable);
		void UpdateAnalysisAndWait();
		void UpdateAnalysis();
		void AbortAnalysis();

		void DefineDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type);
		void DefineUserDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type);
		void UndefineDataVariable(uint64_t addr);
		void UndefineUserDataVariable(uint64_t addr);

		std::map<uint64_t, DataVariable> GetDataVariables();
		bool GetDataVariableAtAddress(uint64_t addr, DataVariable& var);

		std::vector<Ref<Function>> GetAnalysisFunctionList();
		bool HasFunctions() const;
		Ref<Function> GetAnalysisFunction(Platform* platform, uint64_t addr);
		Ref<Function> GetRecentAnalysisFunctionForAddress(uint64_t addr);
		std::vector<Ref<Function>> GetAnalysisFunctionsForAddress(uint64_t addr);
		std::vector<Ref<Function>> GetAnalysisFunctionsContainingAddress(uint64_t addr);
		Ref<Function> GetAnalysisEntryPoint();

		Ref<BasicBlock> GetRecentBasicBlockForAddress(uint64_t addr);
		std::vector<Ref<BasicBlock>> GetBasicBlocksForAddress(uint64_t addr);
		std::vector<Ref<BasicBlock>> GetBasicBlocksStartingAtAddress(uint64_t addr);

		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr);
		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr, uint64_t len);
		std::vector<uint64_t> GetCodeReferencesFrom(ReferenceSource src);
		std::vector<uint64_t> GetCodeReferencesFrom(ReferenceSource src, uint64_t len);

		std::vector<uint64_t> GetDataReferences(uint64_t addr);
		std::vector<uint64_t> GetDataReferences(uint64_t addr, uint64_t len);
		std::vector<uint64_t> GetDataReferencesFrom(uint64_t addr);
		std::vector<uint64_t> GetDataReferencesFrom(uint64_t addr, uint64_t len);
		void AddUserDataReference(uint64_t fromAddr, uint64_t toAddr);
		void RemoveUserDataReference(uint64_t fromAddr, uint64_t toAddr);

		// References to type
		std::vector<ReferenceSource> GetCodeReferencesForType(const QualifiedName& type);
		std::vector<uint64_t> GetDataReferencesForType(const QualifiedName& type);
		std::vector<TypeReferenceSource> GetTypeReferencesForType(const QualifiedName& type);

		// References to type field
		std::vector<TypeFieldReference> GetCodeReferencesForTypeField(const QualifiedName& type, uint64_t offset);
		std::vector<uint64_t> GetDataReferencesForTypeField(const QualifiedName& type, uint64_t offset);
		std::vector<TypeReferenceSource> GetTypeReferencesForTypeField(const QualifiedName& type, uint64_t offset);

		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFrom(ReferenceSource src);
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFrom(ReferenceSource src, uint64_t len);
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFieldFrom(ReferenceSource src);
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFieldFrom(ReferenceSource src, uint64_t len);

		std::vector<uint64_t> GetAllFieldsReferenced(const QualifiedName& type);
		std::map<uint64_t, std::vector<size_t>> GetAllSizesReferenced(const QualifiedName& type);
		std::map<uint64_t, std::vector<Confidence<Ref<Type>>>> GetAllTypesReferenced(const QualifiedName& type);
		std::vector<size_t> GetSizesReferenced(const QualifiedName& type, uint64_t offset);
		std::vector<Confidence<Ref<Type>>> GetTypesReferenced(const QualifiedName& type, uint64_t offset);

		Ref<Structure> CreateStructureBasedOnFieldAccesses(const QualifiedName& type);

		std::vector<uint64_t> GetCallees(ReferenceSource addr);
		std::vector<ReferenceSource> GetCallers(uint64_t addr);

		Ref<Symbol> GetSymbolByAddress(uint64_t addr, const NameSpace& nameSpace = NameSpace());
		Ref<Symbol> GetSymbolByRawName(const std::string& name, const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetSymbolsByName(const std::string& name, const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetSymbols(const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetSymbols(uint64_t start, uint64_t len, const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetSymbolsOfType(BNSymbolType type, const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetSymbolsOfType(
			BNSymbolType type, uint64_t start, uint64_t len, const NameSpace& nameSpace = NameSpace());
		std::vector<Ref<Symbol>> GetVisibleSymbols(const NameSpace& nameSpace = NameSpace());

		void DefineAutoSymbol(Ref<Symbol> sym);
		Ref<Symbol> DefineAutoSymbolAndVariableOrFunction(Ref<Platform> platform, Ref<Symbol> sym, Ref<Type> type);
		void UndefineAutoSymbol(Ref<Symbol> sym);

		void DefineUserSymbol(Ref<Symbol> sym);
		void UndefineUserSymbol(Ref<Symbol> sym);

		void DefineImportedFunction(Ref<Symbol> importAddressSym, Ref<Function> func, Ref<Type> type = nullptr);

		void BeginBulkModifySymbols();
		void EndBulkModifySymbols();

		void AddTagType(Ref<TagType> tagType);
		void RemoveTagType(Ref<TagType> tagType);
		Ref<TagType> GetTagType(const std::string& name);
		Ref<TagType> GetTagType(const std::string& name, TagType::Type type);
		Ref<TagType> GetTagTypeByName(const std::string& name);
		Ref<TagType> GetTagTypeByName(const std::string& name, TagType::Type type);
		Ref<TagType> GetTagTypeById(const std::string& id);
		Ref<TagType> GetTagTypeById(const std::string& id, TagType::Type type);
		std::vector<Ref<TagType>> GetTagTypes();

		void AddTag(Ref<Tag> tag, bool user = false);
		void RemoveTag(Ref<Tag> tag, bool user = false);
		Ref<Tag> GetTag(const std::string& tagId);

		std::vector<TagReference> GetAllTagReferences();
		std::vector<TagReference> GetAllAddressTagReferences();
		std::vector<TagReference> GetAllFunctionTagReferences();
		std::vector<TagReference> GetAllTagReferencesOfType(Ref<TagType> tagType);

		std::vector<TagReference> GetTagReferencesOfType(Ref<TagType> tagType);
		size_t GetTagReferencesOfTypeCount(Ref<TagType> tagType);
		size_t GetAllTagReferencesOfTypeCount(Ref<TagType> tagType);
		std::map<Ref<TagType>, size_t> GetAllTagReferenceTypeCounts();

		std::vector<TagReference> GetDataTagReferences();
		std::vector<TagReference> GetAutoDataTagReferences();
		std::vector<TagReference> GetUserDataTagReferences();
		std::vector<Ref<Tag>> GetDataTags(uint64_t addr);
		std::vector<Ref<Tag>> GetAutoDataTags(uint64_t addr);
		std::vector<Ref<Tag>> GetUserDataTags(uint64_t addr);
		std::vector<Ref<Tag>> GetDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetAutoDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetUserDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		std::vector<TagReference> GetDataTagsInRange(uint64_t start, uint64_t end);
		std::vector<TagReference> GetAutoDataTagsInRange(uint64_t start, uint64_t end);
		std::vector<TagReference> GetUserDataTagsInRange(uint64_t start, uint64_t end);
		void AddAutoDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveAutoDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveAutoDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		void AddUserDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveUserDataTag(uint64_t addr, Ref<Tag> tag);
		void RemoveUserDataTagsOfType(uint64_t addr, Ref<TagType> tagType);
		void RemoveTagReference(const TagReference& ref);

		Ref<Tag> CreateAutoDataTag(
			uint64_t addr, const std::string& tagTypeName, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserDataTag(
			uint64_t addr, const std::string& tagTypeName, const std::string& data, bool unique = false);

		Ref<Tag> CreateAutoDataTag(uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserDataTag(uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);

		bool CanAssemble(Architecture* arch);

		bool IsNeverBranchPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsAlwaysBranchPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsInvertBranchPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsSkipAndReturnZeroPatchAvailable(Architecture* arch, uint64_t addr);
		bool IsSkipAndReturnValuePatchAvailable(Architecture* arch, uint64_t addr);
		bool ConvertToNop(Architecture* arch, uint64_t addr);
		bool AlwaysBranch(Architecture* arch, uint64_t addr);
		bool InvertBranch(Architecture* arch, uint64_t addr);
		bool SkipAndReturnValue(Architecture* arch, uint64_t addr, uint64_t value);
		size_t GetInstructionLength(Architecture* arch, uint64_t addr);

		bool GetStringAtAddress(uint64_t addr, BNStringReference& strRef);
		std::vector<BNStringReference> GetStrings();
		std::vector<BNStringReference> GetStrings(uint64_t start, uint64_t len);

		Ref<AnalysisCompletionEvent> AddAnalysisCompletionEvent(const std::function<void()>& callback);

		AnalysisInfo GetAnalysisInfo();
		BNAnalysisProgress GetAnalysisProgress();
		Ref<BackgroundTask> GetBackgroundAnalysisTask();

		uint64_t GetNextFunctionStartAfterAddress(uint64_t addr);
		uint64_t GetNextBasicBlockStartAfterAddress(uint64_t addr);
		uint64_t GetNextDataAfterAddress(uint64_t addr);
		uint64_t GetNextDataVariableStartAfterAddress(uint64_t addr);
		uint64_t GetPreviousFunctionStartBeforeAddress(uint64_t addr);
		uint64_t GetPreviousBasicBlockStartBeforeAddress(uint64_t addr);
		uint64_t GetPreviousBasicBlockEndBeforeAddress(uint64_t addr);
		uint64_t GetPreviousDataBeforeAddress(uint64_t addr);
		uint64_t GetPreviousDataVariableStartBeforeAddress(uint64_t addr);

		bool ParsePossibleValueSet(const std::string& value, BNRegisterValueType state, PossibleValueSet& result,
			uint64_t here, std::string& errors);

		bool ParseTypeString(const std::string& text, QualifiedNameAndType& result, std::string& errors,
			const std::set<QualifiedName>& typesAllowRedefinition = {});
		bool ParseTypeString(const std::string& text, std::map<QualifiedName, Ref<Type>>& types,
			std::map<QualifiedName, Ref<Type>>& variables, std::map<QualifiedName, Ref<Type>>& functions,
			std::string& errors, const std::set<QualifiedName>& typesAllowRedefinition = {});
		bool ParseTypesFromSource(const std::string& text, const std::vector<std::string>& options, const std::vector<std::string>& includeDirs, TypeParserResult& result,
			std::string& errors, const std::set<QualifiedName>& typesAllowRedefinition = {});

		std::map<QualifiedName, Ref<Type>> GetTypes();
		std::vector<QualifiedName> GetTypeNames(const std::string& matching = "");
		Ref<Type> GetTypeByName(const QualifiedName& name);
		Ref<Type> GetTypeById(const std::string& id);
		std::string GetTypeId(const QualifiedName& name);
		QualifiedName GetTypeNameById(const std::string& id);
		bool IsTypeAutoDefined(const QualifiedName& name);
		QualifiedName DefineType(const std::string& id, const QualifiedName& defaultName, Ref<Type> type);
		void DefineTypes(const std::vector<std::pair<std::string, QualifiedNameAndType>>& types, std::function<bool(size_t, size_t)> progress = {});
		void DefineUserType(const QualifiedName& name, Ref<Type> type);
		void DefineUserTypes(const std::vector<QualifiedNameAndType>& types, std::function<bool(size_t, size_t)> progress = {});
		void UndefineType(const std::string& id);
		void UndefineUserType(const QualifiedName& name);
		void RenameType(const QualifiedName& oldName, const QualifiedName& newName);

		void RegisterPlatformTypes(Platform* platform);

		bool FindNextData(
			uint64_t start, const DataBuffer& data, uint64_t& result, BNFindFlag flags = FindCaseSensitive);
		bool FindNextText(uint64_t start, const std::string& data, uint64_t& result, Ref<DisassemblySettings> settings,
			BNFindFlag flags = FindCaseSensitive, BNFunctionGraphType graph = NormalFunctionGraph);
		bool FindNextConstant(uint64_t start, uint64_t constant, uint64_t& result, Ref<DisassemblySettings> settings,
			BNFunctionGraphType graph = NormalFunctionGraph);

		bool FindNextData(uint64_t start, uint64_t end, const DataBuffer& data, uint64_t& addr, BNFindFlag flags,
			const std::function<bool(size_t current, size_t total)>& progress);
		bool FindNextText(uint64_t start, uint64_t end, const std::string& data, uint64_t& addr,
			Ref<DisassemblySettings> settings, BNFindFlag flags, BNFunctionGraphType graph,
			const std::function<bool(size_t current, size_t total)>& progress);
		bool FindNextConstant(uint64_t start, uint64_t end, uint64_t constant, uint64_t& addr,
			Ref<DisassemblySettings> settings, BNFunctionGraphType graph,
			const std::function<bool(size_t current, size_t total)>& progress);

		bool FindAllData(uint64_t start, uint64_t end, const DataBuffer& data, BNFindFlag flags,
			const std::function<bool(size_t current, size_t total)>& progress,
			const std::function<bool(uint64_t addr, const DataBuffer& match)>& matchCallback);
		bool FindAllText(uint64_t start, uint64_t end, const std::string& data, Ref<DisassemblySettings> settings,
			BNFindFlag flags, BNFunctionGraphType graph,
			const std::function<bool(size_t current, size_t total)>& progress,
			const std::function<bool(uint64_t addr, const std::string& match, const LinearDisassemblyLine& line)>&
				matchCallback);
		bool FindAllConstant(uint64_t start, uint64_t end, uint64_t constant, Ref<DisassemblySettings> settings,
			BNFunctionGraphType graph, const std::function<bool(size_t current, size_t total)>& progress,
			const std::function<bool(uint64_t addr, const LinearDisassemblyLine& line)>& matchCallback);

		void Reanalyze();

		Ref<Workflow> GetWorkflow() const;

		void ShowPlainTextReport(const std::string& title, const std::string& contents);
		void ShowMarkdownReport(const std::string& title, const std::string& contents, const std::string& plainText);
		void ShowHTMLReport(const std::string& title, const std::string& contents, const std::string& plainText);
		void ShowGraphReport(const std::string& title, FlowGraph* graph);
		bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);
		bool GetAddressInput(
			uint64_t& result, const std::string& prompt, const std::string& title, uint64_t currentAddress);

		void AddAutoSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
		void RemoveAutoSegment(uint64_t start, uint64_t length);
		void AddUserSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);
		void RemoveUserSegment(uint64_t start, uint64_t length);
		std::vector<Ref<Segment>> GetSegments();
		Ref<Segment> GetSegmentAt(uint64_t addr);
		bool GetAddressForDataOffset(uint64_t offset, uint64_t& addr);

		void AddAutoSection(const std::string& name, uint64_t start, uint64_t length,
			BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "", uint64_t align = 1,
			uint64_t entrySize = 0, const std::string& linkedSection = "", const std::string& infoSection = "",
			uint64_t infoData = 0);
		void RemoveAutoSection(const std::string& name);
		void AddUserSection(const std::string& name, uint64_t start, uint64_t length,
			BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "", uint64_t align = 1,
			uint64_t entrySize = 0, const std::string& linkedSection = "", const std::string& infoSection = "",
			uint64_t infoData = 0);
		void RemoveUserSection(const std::string& name);
		std::vector<Ref<Section>> GetSections();
		std::vector<Ref<Section>> GetSectionsAt(uint64_t addr);
		Ref<Section> GetSectionByName(const std::string& name);

		std::vector<std::string> GetUniqueSectionNames(const std::vector<std::string>& names);

		std::string GetCommentForAddress(uint64_t addr) const;
		std::vector<uint64_t> GetCommentedAddresses() const;
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

		std::vector<BNAddressRange> GetAllocatedRanges();

		void StoreMetadata(const std::string& key, Ref<Metadata> value, bool isAuto = false);
		Ref<Metadata> QueryMetadata(const std::string& key);
		void RemoveMetadata(const std::string& key);
		std::string GetStringMetadata(const std::string& key);
		std::vector<uint8_t> GetRawMetadata(const std::string& key);
		uint64_t GetUIntMetadata(const std::string& key);

		std::vector<std::string> GetLoadSettingsTypeNames();
		Ref<Settings> GetLoadSettings(const std::string& typeName);
		void SetLoadSettings(const std::string& typeName, Ref<Settings> settings);

		BNAnalysisParameters GetParametersForAnalysis();
		void SetParametersForAnalysis(BNAnalysisParameters params);
		uint64_t GetMaxFunctionSizeForAnalysis();
		void SetMaxFunctionSizeForAnalysis(uint64_t size);
		bool GetNewAutoFunctionAnalysisSuppressed();
		void SetNewAutoFunctionAnalysisSuppressed(bool suppress);

		std::set<NameSpace> GetNameSpaces() const;
		static NameSpace GetInternalNameSpace();
		static NameSpace GetExternalNameSpace();

		static bool ParseExpression(Ref<BinaryView> view, const std::string& expression, uint64_t& offset,
			uint64_t here, std::string& errorString);
		bool HasSymbols() const;
		bool HasDataVariables() const;

		Ref<Structure> CreateStructureFromOffsetAccess(const QualifiedName& type, bool* newMemberAdded) const;
		Confidence<Ref<Type>> CreateStructureMemberFromAccess(const QualifiedName& name, uint64_t offset) const;

		Ref<Logger> CreateLogger(const std::string& name);
	};


	class Symbol : public CoreRefCountObject<BNSymbol, BNNewSymbolReference, BNFreeSymbol>
	{
	  public:
		Symbol(BNSymbolType type, const std::string& shortName, const std::string& fullName, const std::string& rawName,
		    uint64_t addr, BNSymbolBinding binding = NoBinding,
		    const NameSpace& nameSpace = NameSpace(DEFAULT_INTERNAL_NAMESPACE), uint64_t ordinal = 0);
		Symbol(BNSymbolType type, const std::string& name, uint64_t addr, BNSymbolBinding binding = NoBinding,
		    const NameSpace& nameSpace = NameSpace(DEFAULT_INTERNAL_NAMESPACE), uint64_t ordinal = 0);
		Symbol(BNSymbol* sym);

		BNSymbolType GetType() const;
		BNSymbolBinding GetBinding() const;
		std::string GetShortName() const;
		std::string GetFullName() const;
		std::string GetRawName() const;
		uint64_t GetAddress() const;
		uint64_t GetOrdinal() const;
		bool IsAutoDefined() const;
		NameSpace GetNameSpace() const;

		static Ref<Symbol> ImportedFunctionFromImportAddressSymbol(Symbol* sym, uint64_t addr);
	};

	class AnalysisCompletionEvent :
	    public CoreRefCountObject<BNAnalysisCompletionEvent, BNNewAnalysisCompletionEventReference,
	        BNFreeAnalysisCompletionEvent>
	{
	  protected:
		std::function<void()> m_callback;
		std::recursive_mutex m_mutex;

		static void CompletionCallback(void* ctxt);

	  public:
		AnalysisCompletionEvent(BinaryView* view, const std::function<void()>& callback);
		void Cancel();
	};

	class QueryMetadataException : public std::exception
	{
		const std::string m_error;

	  public:
		QueryMetadataException(const std::string& error) : std::exception(), m_error(error) {}
		virtual const char* what() const NOEXCEPT { return m_error.c_str(); }
	};

	class BinaryData : public BinaryView
	{
	  public:
		BinaryData(FileMetadata* file);
		BinaryData(FileMetadata* file, const DataBuffer& data);
		BinaryData(FileMetadata* file, const void* data, size_t len);
		BinaryData(FileMetadata* file, const std::string& path);
		BinaryData(FileMetadata* file, FileAccessor* accessor);
	};

	/*!
	    OpenView opens a file on disk and returns a BinaryView, attempting to use the most
	    relevant BinaryViewType and generating default load options (which are overridable).

	    If there is any error loading the file, nullptr will be returned and a log error will
	    be printed.

	    Warning: You will need to call bv->GetFile()->Close() when you are finished using the
	    view returned by this function to free the resources it opened.

	    If no BinaryViewType is available to load the file, the `Mapped` view type will
	    attempt to load it, and will try to auto-detect the architecture. If no architecture
	    is detected or specified in the load options, the `Mapped` type will fail and this
	    function will also return nullptr.

	    Note: Although general container file support is not complete, support for Universal
	    archives exists. It's possible to control the architecture preference with the
	    `files.universal.architecturePreference` setting. This setting is scoped to
	    SettingsUserScope and can be modified as follows:

	        Json::Value options(Json::objectValue);
	        options["files.universal.architecturePreference"] = Json::Value(Json::arrayValue);
	        options["files.universal.architecturePreference"].append("arm64");
	        Ref<BinaryView> bv = OpenView("/bin/ls", true, {}, options);

	    \param filename Path to filename or BNDB to open.
	    \param updateAnalysis If true, UpdateAnalysisAndWait() will be called after opening
	                          a BinaryView.
	    \param progress Optional function to be called with progress updates as the view is
	                    being loaded. If the function returns false, it will cancel OpenView.
	    \param options A Json object whose keys are setting identifiers and whose values are
	                   the desired settings.
	    \return Constructed view, or a nullptr Ref<BinaryView>
	 */
	Ref<BinaryView> OpenView(const std::string& filename, bool updateAnalysis = true, std::function<bool(size_t, size_t)> progress = {}, Json::Value options = Json::Value(Json::objectValue));

	/*!
	    Open a BinaryView from a raw data buffer, initializing data views and loading settings.

	    See BinaryNinja::OpenView(const std::string&, bool, std::function<bool(size_t, size_t)>, Json::Value)
	    for discussion of this function.

	    \param rawData Buffer with raw binary data to load (cannot load from bndb)
	    \param updateAnalysis If true, UpdateAnalysisAndWait() will be called after opening
	                          a BinaryView.
	    \param progress Optional function to be called with progress updates as the view is
	                    being loaded. If the function returns false, it will cancel OpenView.
	    \param options A Json object whose keys are setting identifiers and whose values are
	                   the desired settings.
	    \return Constructed view, or a nullptr Ref<BinaryView>
	 */
	Ref<BinaryView> OpenView(const DataBuffer& rawData, bool updateAnalysis = true, std::function<bool(size_t, size_t)> progress = {}, Json::Value options = Json::Value(Json::objectValue));


	/*!
	    Open a BinaryView from a raw BinaryView, initializing data views and loading settings.

	    See BinaryNinja::OpenView(const std::string&, bool, std::function<bool(size_t, size_t)>, Json::Value)
	    for discussion of this function.

	    \param rawData BinaryView with raw binary data to load
	    \param updateAnalysis If true, UpdateAnalysisAndWait() will be called after opening
	                          a BinaryView.
	    \param progress Optional function to be called with progress updates as the view is
	                    being loaded. If the function returns false, it will cancel OpenView.
	    \param options A Json object whose keys are setting identifiers and whose values are
	                   the desired settings.
	    \param isDatabase True if the view being loaded is the raw view of an already opened database.
	    \return Constructed view, or a nullptr Ref<BinaryView>
	 */
	Ref<BinaryView> OpenView(Ref<BinaryView> rawData, bool updateAnalysis = true, std::function<bool(size_t, size_t)> progress = {}, Json::Value options = Json::Value(Json::objectValue), bool isDatabase = false);

}