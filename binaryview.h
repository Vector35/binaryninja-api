#pragma once

#include "binaryninjacore.h"
#include "confidence.h"
#include "namelist.h"
#include "refcount.h"
#include "tag.h"
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>

namespace BinaryNinja
{
	class Architecture;
	class BackgroundTask;
	class BasicBlock;
	class BinaryView;
	class Component;
	class DataBuffer;
	struct DataVariable;
	class DebugInfo;
	class DisassemblySettings;
	class ExternalLibrary;
	class ExternalLocation;
	class FileAccessor;
	class FileMetadata;
	class FlowGraph;
	class Function;
	struct LinearDisassemblyLine;
	class Logger;
	class MemoryMap;
	class Metadata;
	class NamedTypeReference;
	struct ParsedType;
	class Platform;
	struct PossibleValueSet;
	class ProjectFile;
	class QualifiedName;
	struct QualifiedNameAndType;
	struct ReferenceSource;
	class Relocation;
	class Section;
	class Segment;
	class Settings;
	class Structure;
	class Symbol;
	class Type;
	class TypeArchive;
	struct TypeFieldReference;
	class TypeLibrary;
	struct TypeParserResult;
	struct TypeReferenceSource;
	class UndoEntry;
	class Workflow;


	/*!
		\ingroup binaryview
	*/
	class SaveSettings : public CoreRefCountObject<BNSaveSettings, BNNewSaveSettingsReference, BNFreeSaveSettings>
	{
	  public:
		SaveSettings();
		SaveSettings(BNSaveSettings* settings);

		bool IsOptionSet(BNSaveOption option) const;
		void SetOption(BNSaveOption option, bool state = true);

		std::string GetName() const;
		void SetName(const std::string& name);
	};


	/*!

		\ingroup binaryview
	*/
	class BinaryDataNotification
	{
	  private:
		BNBinaryDataNotification m_callbacks;

		static uint64_t NotificationBarrierCallback(void* ctxt, BNBinaryView* object);
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
		static void SymbolRemovedCallback(void* ctxt, BNBinaryView* view, BNSymbol* sym);
		static void SymbolUpdatedCallback(void* ctxt, BNBinaryView* view, BNSymbol* sym);

		static void DataMetadataUpdatedCallback(void* ctxt, BNBinaryView* object, uint64_t offset);
		static void TagTypeUpdatedCallback(void* ctxt, BNBinaryView* object, BNTagType* tagType);
		static void TagAddedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);
		static void TagRemovedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);
		static void TagUpdatedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef);

		static void StringFoundCallback(void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);
		static void StringRemovedCallback(void* ctxt, BNBinaryView* data, BNStringType type, uint64_t offset, size_t len);
		static void TypeDefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeUndefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeReferenceChangedCallback(void* ctx, BNBinaryView* data, BNQualifiedName* name, BNType* type);
		static void TypeFieldReferenceChangedCallback(void* ctx, BNBinaryView* data, BNQualifiedName* name, uint64_t offset);
		static void SegmentAddedCallback(void* ctx, BNBinaryView* data, BNSegment* segment);
		static void SegmentRemovedCallback(void* ctx, BNBinaryView* data, BNSegment* segment);
		static void SegmentUpdatedCallback(void* ctx, BNBinaryView* data, BNSegment* segment);

		static void SectionAddedCallback(void* ctx, BNBinaryView* data, BNSection* section);
		static void SectionRemovedCallback(void* ctx, BNBinaryView* data, BNSection* section);
		static void SectionUpdatedCallback(void* ctx, BNBinaryView* data, BNSection* section);

		static void ComponentNameUpdatedCallback(void* ctxt, BNBinaryView* data, char* previousName, BNComponent* component);
		static void ComponentAddedCallback(void* ctxt, BNBinaryView* data, BNComponent* component);
		static void ComponentRemovedCallback(void* ctxt, BNBinaryView* data, BNComponent* formerParent, BNComponent* component);
		static void ComponentMovedCallback(void* ctxt, BNBinaryView* data, BNComponent* formerParent, BNComponent* newParent, BNComponent* component);
		static void ComponentFunctionAddedCallback(void* ctxt, BNBinaryView* data, BNComponent* component, BNFunction* function);
		static void ComponentFunctionRemovedCallback(void* ctxt, BNBinaryView* data, BNComponent* component, BNFunction* function);
		static void ComponentDataVariableAddedCallback(void* ctxt, BNBinaryView* data, BNComponent* component, BNDataVariable* var);
		static void ComponentDataVariableRemovedCallback(void* ctxt, BNBinaryView* data, BNComponent* component, BNDataVariable* var);

		static void ExternalLibraryAddedCallback(void* ctxt, BNBinaryView* data, BNExternalLibrary* library);
		static void ExternalLibraryUpdatedCallback(void* ctxt, BNBinaryView* data, BNExternalLibrary* library);
		static void ExternalLibraryRemovedCallback(void* ctxt, BNBinaryView* data, BNExternalLibrary* library);
		static void ExternalLocationAddedCallback(void* ctxt, BNBinaryView* data, BNExternalLocation* location);
		static void ExternalLocationUpdatedCallback(void* ctxt, BNBinaryView* data, BNExternalLocation* location);
		static void ExternalLocationRemovedCallback(void* ctxt, BNBinaryView* data, BNExternalLocation* location);

		static void TypeArchiveAttachedCallback(void* ctxt, BNBinaryView* data, const char* id, const char* path);
		static void TypeArchiveDetachedCallback(void* ctxt, BNBinaryView* data, const char* id, const char* path);
		static void TypeArchiveConnectedCallback(void* ctxt, BNBinaryView* data, BNTypeArchive* archive);
		static void TypeArchiveDisconnectedCallback(void* ctxt, BNBinaryView* data, BNTypeArchive* archive);

		static void UndoEntryAddedCallback(void* ctxt, BNBinaryView* data, BNUndoEntry* entry);
		static void UndoEntryTakenCallback(void* ctxt, BNBinaryView* data, BNUndoEntry* entry);
		static void RedoEntryTakenCallback(void* ctxt, BNBinaryView* data, BNUndoEntry* entry);

		static void RebasedCallback(void* ctxt, BNBinaryView* oldView, BNBinaryView* newView);

	  public:

		enum NotificationType : uint64_t
		{
			NotificationBarrier = 1ULL << 0,
			DataWritten = 1ULL << 1,
			DataInserted = 1ULL << 2,
			DataRemoved = 1ULL << 3,
			FunctionAdded = 1ULL << 4,
			FunctionRemoved = 1ULL << 5,
			FunctionUpdated = 1ULL << 6,
			FunctionUpdateRequested = 1ULL << 7,
			DataVariableAdded = 1ULL << 8,
			DataVariableRemoved = 1ULL << 9,
			DataVariableUpdated = 1ULL << 10,
			DataMetadataUpdated = 1ULL << 11,
			TagTypeUpdated = 1ULL << 12,
			TagAdded = 1ULL << 13,
			TagRemoved = 1ULL << 14,
			TagUpdated = 1ULL << 15,
			SymbolAdded = 1ULL << 16,
			SymbolRemoved = 1ULL << 17,
			SymbolUpdated = 1ULL << 18,
			StringFound = 1ULL << 19,
			StringRemoved = 1ULL << 20,
			TypeDefined = 1ULL << 21,
			TypeUndefined = 1ULL << 22,
			TypeReferenceChanged = 1ULL << 23,
			TypeFieldReferenceChanged = 1ULL << 24,
			SegmentAdded = 1ULL << 25,
			SegmentRemoved = 1ULL << 26,
			SegmentUpdated = 1ULL << 27,
			SectionAdded = 1ULL << 28,
			SectionRemoved = 1ULL << 29,
			SectionUpdated = 1ULL << 30,
			ComponentNameUpdated = 1ULL << 31,
			ComponentAdded = 1ULL << 32,
			ComponentRemoved = 1ULL << 33,
			ComponentMoved = 1ULL << 34,
			ComponentFunctionAdded = 1ULL << 35,
			ComponentFunctionRemoved = 1ULL << 36,
			ComponentDataVariableAdded = 1ULL << 37,
			ComponentDataVariableRemoved = 1ULL << 38,
			ExternalLibraryAdded = 1ULL << 39,
			ExternalLibraryRemoved = 1ULL << 40,
			ExternalLibraryUpdated = 1ULL << 41,
			ExternalLocationAdded = 1ULL << 42,
			ExternalLocationRemoved = 1ULL << 43,
			ExternalLocationUpdated = 1ULL << 44,
			TypeArchiveAttached = 1ULL << 45,
			TypeArchiveDetached = 1ULL << 46,
			TypeArchiveConnected = 1ULL << 47,
			TypeArchiveDisconnected = 1ULL << 48,
			UndoEntryAdded = 1ULL << 49,
			UndoEntryTaken = 1ULL << 50,
			RedoEntryTaken = 1ULL << 51,
			Rebased = 1ULL << 52,

			BinaryDataUpdates = DataWritten | DataInserted | DataRemoved,
			FunctionLifetime = FunctionAdded | FunctionRemoved,
			FunctionUpdates = FunctionLifetime | FunctionUpdated,
			DataVariableLifetime = DataVariableAdded | DataVariableRemoved,
			DataVariableUpdates = DataVariableLifetime | DataVariableUpdated,
			TagLifetime = TagAdded | TagRemoved,
			TagUpdates = TagLifetime | TagUpdated,
			SymbolLifetime = SymbolAdded | SymbolRemoved,
			SymbolUpdates = SymbolLifetime | SymbolUpdated,
			StringUpdates = StringFound | StringRemoved,
			TypeLifetime = TypeDefined | TypeUndefined,
			TypeUpdates = TypeLifetime | TypeReferenceChanged | TypeFieldReferenceChanged,
			SegmentLifetime = SegmentAdded | SegmentRemoved,
			SegmentUpdates = SegmentLifetime | SegmentUpdated,
			SectionLifetime = SectionAdded | SectionRemoved,
			SectionUpdates = SectionLifetime | SectionUpdated,
			ComponentUpdates = ComponentNameUpdated | ComponentAdded | ComponentRemoved | ComponentMoved | ComponentFunctionAdded | ComponentFunctionRemoved | ComponentDataVariableAdded | ComponentDataVariableRemoved,
			ExternalLibraryLifetime = ExternalLibraryAdded | ExternalLibraryRemoved,
			ExternalLibraryUpdates = ExternalLibraryLifetime | ExternalLibraryUpdated,
			ExternalLocationLifetime = ExternalLocationAdded | ExternalLocationRemoved,
			ExternalLocationUpdates = ExternalLocationLifetime | ExternalLocationUpdated,
			TypeArchiveUpdates = TypeArchiveAttached | TypeArchiveDetached | TypeArchiveConnected | TypeArchiveDisconnected,
			UndoUpdates = UndoEntryAdded | UndoEntryTaken | RedoEntryTaken
		};

		using NotificationTypes = uint64_t;

		BinaryDataNotification();
		BinaryDataNotification(NotificationTypes notifications);

		virtual ~BinaryDataNotification() {}

		BNBinaryDataNotification* GetCallbacks() { return &m_callbacks; }

		virtual uint64_t OnNotificationBarrier(BinaryView* view)
		{
			(void)view;
			return 0;
		}
		virtual void OnBinaryDataWritten(BinaryView* view, uint64_t offset, size_t len)
		{
			(void)view;
			(void)offset;
			(void)len;
		}
		virtual void OnBinaryDataInserted(BinaryView* view, uint64_t offset, size_t len)
		{
			(void)view;
			(void)offset;
			(void)len;
		}
		virtual void OnBinaryDataRemoved(BinaryView* view, uint64_t offset, uint64_t len)
		{
			(void)view;
			(void)offset;
			(void)len;
		}
		virtual void OnAnalysisFunctionAdded(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnAnalysisFunctionRemoved(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnAnalysisFunctionUpdated(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnAnalysisFunctionUpdateRequested(BinaryView* view, Function* func)
		{
			(void)view;
			(void)func;
		}
		virtual void OnDataVariableAdded(BinaryView* view, const DataVariable& var)
		{
			(void)view;
			(void)var;
		}
		virtual void OnDataVariableRemoved(BinaryView* view, const DataVariable& var)
		{
			(void)view;
			(void)var;
		}
		virtual void OnDataVariableUpdated(BinaryView* view, const DataVariable& var)
		{
			(void)view;
			(void)var;
		}
		virtual void OnDataMetadataUpdated(BinaryView* view, uint64_t offset)
		{
			(void)view;
			(void)offset;
		}
		virtual void OnTagTypeUpdated(BinaryView* view, Ref<TagType> tagTypeRef)
		{
			(void)view;
			(void)tagTypeRef;
		}
		virtual void OnTagAdded(BinaryView* view, const TagReference& tagRef)
		{
			(void)view;
			(void)tagRef;
		}
		virtual void OnTagRemoved(BinaryView* view, const TagReference& tagRef)
		{
			(void)view;
			(void)tagRef;
		}
		virtual void OnTagUpdated(BinaryView* view, const TagReference& tagRef)
		{
			(void)view;
			(void)tagRef;
		}
		virtual void OnSymbolAdded(BinaryView* view, Symbol* sym)
		{
			(void)view;
			(void)sym;
		}
		virtual void OnSymbolRemoved(BinaryView* view, Symbol* sym)
		{
			(void)view;
			(void)sym;
		}
		virtual void OnSymbolUpdated(BinaryView* view, Symbol* sym)
		{
			(void)view;
			(void)sym;
		}
		virtual void OnStringFound(BinaryView* data, BNStringType type, uint64_t offset, size_t len)
		{
			(void)data;
			(void)type;
			(void)offset;
			(void)len;
		}
		virtual void OnStringRemoved(BinaryView* data, BNStringType type, uint64_t offset, size_t len)
		{
			(void)data;
			(void)type;
			(void)offset;
			(void)len;
		}
		virtual void OnTypeDefined(BinaryView* data, const QualifiedName& name, Type* type)
		{
			(void)data;
			(void)name;
			(void)type;
		}
		virtual void OnTypeUndefined(BinaryView* data, const QualifiedName& name, Type* type)
		{
			(void)data;
			(void)name;
			(void)type;
		}
		virtual void OnTypeReferenceChanged(BinaryView* data, const QualifiedName& name, Type* type)
		{
			(void)data;
			(void)name;
			(void)type;
		}
		virtual void OnTypeFieldReferenceChanged(BinaryView* data, const QualifiedName& name, uint64_t offset)
		{
			(void)data;
			(void)name;
			(void)offset;
		}
		virtual void OnSegmentAdded(BinaryView* data, Segment* segment)
		{
			(void)data;
			(void)segment;
		}
		virtual void OnSegmentRemoved(BinaryView* data, Segment* segment)
		{
			(void)data;
			(void)segment;
		}
		virtual void OnSegmentUpdated(BinaryView* data, Segment* segment)
		{
			(void)data;
			(void)segment;
		}
		virtual void OnSectionAdded(BinaryView* data, Section* section)
		{
			(void)data;
			(void)section;
		}
		virtual void OnSectionRemoved(BinaryView* data, Section* section)
		{
			(void)data;
			(void)section;
		}
		virtual void OnSectionUpdated(BinaryView* data, Section* section)
		{
			(void)data;
			(void)section;
		}

		/*! This notification is posted after the display name for a component is updated.

			\param data BinaryView the Component is contained in
		 	\param previousName Previous name of the component
			\param component The component which was modified.
		*/
		virtual void OnComponentNameUpdated(BinaryView* data, std::string& previousName, Component* component)
		{
			(void)data;
			(void)previousName;
			(void)component;
		}

		/*! This notification is posted after a Component is added to the tree.

		 	\param data BinaryView the Component was added to
		 	\param component Component which was added.
		*/
		virtual void OnComponentAdded(BinaryView* data, Component* component)
		{
			(void)data;
			(void)component;
		}

		/*! This notification is posted after a Component is removed from the tree.

		 	\param data BinaryView the Component was removed from
		 	\param formerParent Former parent of the Component
		 	\param component
		 	\parblock
		    The removed and now "dead" Component object.

		    This "dead" Component can no longer be moved to other components or have components added to it. It
		    should not be used after this point for storing any objects, and will be destroyed once no more references
		    are held to it.
		 	\endparblock
		*/
		virtual void OnComponentRemoved(BinaryView* data, Component* formerParent, Component* component)
		{
			(void)data;
			(void)formerParent;
			(void)component;
		}

		/*! This notification is posted whenever a component is moved from one component to another.

		    \param data BinaryView the Component was removed from
		    \param formerParent Former parent of the Component
		 	\param newParent New parent which the Component was moved to
		 	\param component The component that was moved.
		*/
		virtual void OnComponentMoved(BinaryView* data, Component* formerParent, Component* newParent, Component* component)
		{
			(void)data;
			(void)formerParent;
			(void)newParent;
			(void)component;
		}

		/*! This notification is posted whenever a Function is added to a Component

		 	\param data BinaryView containing the Component and Function
		 	\param component Component the Function was added to
		 	\param function The Function which was added
		*/
		virtual void OnComponentFunctionAdded(BinaryView* data, Component* component, Function* function)
		{
			(void)data;
			(void)component;
			(void)function;
		}

		/*! This notification is posted whenever a Function is removed from a Component

		 	\param data BinaryView containing the Component and Function
		 	\param component Component the Function was removed from
		 	\param function The Function which was removed
		*/
		virtual void OnComponentFunctionRemoved(BinaryView* data, Component* component, Function* function)
		{
			(void)data;
			(void)component;
			(void)function;
		}

		/*! This notification is posted whenever a DataVariable is added to a Component

		    \param data BinaryView containing the Component and DataVariable
		    \param component Component the DataVariable was added to
		    \param var The DataVariable which was added
		 */
		virtual void OnComponentDataVariableAdded(BinaryView* data, Component* component, const DataVariable& var)
		{
			(void)data;
			(void)component;
			(void)var;
		}

		/*! This notification is posted whenever a DataVariable is removed from a Component

		    \param data BinaryView containing the Component and DataVariable
		    \param component Component the DataVariable was removed from
		    \param var The DataVariable which was removed
		 */
		virtual void OnComponentDataVariableRemoved(BinaryView* data, Component* component, const DataVariable& var)
		{
			(void)data;
			(void)component;
			(void)var;
		}

		virtual void OnExternalLibraryAdded(BinaryView* data, ExternalLibrary* library)
		{
			(void)data;
			(void)library;
		}

		virtual void OnExternalLibraryRemoved(BinaryView* data, ExternalLibrary* library)
		{
			(void)data;
			(void)library;
		}

		virtual void OnExternalLibraryUpdated(BinaryView* data, ExternalLibrary* library)
		{
			(void)data;
			(void)library;
		}

		virtual void OnExternalLocationAdded(BinaryView* data, ExternalLocation* location)
		{
			(void)data;
			(void)location;
		}

		virtual void OnExternalLocationRemoved(BinaryView* data, ExternalLocation* location)
		{
			(void)data;
			(void)location;
		}

		virtual void OnExternalLocationUpdated(BinaryView* data, ExternalLocation* location)
		{
			(void)data;
			(void)location;
		}

		/*! This notification is posted whenever a Type Archive is attached to a Binary View

		    \param data BinaryView target
		    \param id Id of the attached archive
		    \param path Path on disk of the attached archive
		 */
		virtual void OnTypeArchiveAttached(BinaryView* data, const std::string& id, const std::string& path)
		{
			(void)data;
			(void)id;
			(void)path;
		}

		/*! This notification is posted whenever a Type Archive is detached to a Binary View

		    \param data BinaryView target
		    \param id Id of the attached archive
		    \param path Path on disk of the attached archive
		 */
		virtual void OnTypeArchiveDetached(BinaryView* data, const std::string& id, const std::string& path)
		{
			(void)data;
			(void)id;
			(void)path;
		}
		/*! This notification is posted whenever a previously disconnected Type Archive
		    attached to the Binary View is connected

		    \param data BinaryView the archive is attached to
		    \param archive Attached archive
		 */
		virtual void OnTypeArchiveConnected(BinaryView* data, TypeArchive* archive)
		{
			(void)data;
			(void)archive;
		}
		/*! This notification is posted whenever a previously connected Type Archive
		    attached to the Binary View is disconnected

		    \param data BinaryView the archive is attached to
		    \param archive Previously attached archive
		 */
		virtual void OnTypeArchiveDisconnected(BinaryView* data, TypeArchive* archive)
		{
			(void)data;
			(void)archive;
		}

		/*! This notification is posted whenever an entry is added to undo history

		    \param data BinaryView the action was taken on
		    \param entry UndoEntry
		 */
		virtual void OnUndoEntryAdded(BinaryView* data, UndoEntry* entry)
		{
			(void)data;
			(void)entry;
		}

		/*! This notification is posted whenever an action is undone

		    \param data BinaryView the action was taken on
		    \param entry UndoEntry that was undone
		 */
		virtual void OnUndoEntryTaken(BinaryView* data, UndoEntry* entry)
		{
			(void)data;
			(void)entry;
		}

		/*! This notification is posted whenever an action is redone

		    \param data BinaryView the action was taken on
		    \param entry UndoEntry that was redone
		 */
		virtual void OnRedoEntryTaken(BinaryView* data, UndoEntry* entry)
		{
			(void)data;
			(void)entry;
		}

		/*! This notification is posted whenever a binary view is rebased

		    \param oldView BinaryView the old view
		    \param newView BinaryView the new view
		 */
		virtual void OnRebased(BinaryView* oldView, BinaryView* newView)
		{
			(void)oldView;
			(void)newView;
		}
	};

	/*!
		\ingroup binaryview
	*/
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

	/*!
		\ingroup binaryview
	*/
	struct ActiveAnalysisInfo
	{
		Ref<Function> func;
		uint64_t analysisTime;
		size_t updateCount;
		size_t submitCount;

		ActiveAnalysisInfo(Ref<Function> f, uint64_t t, size_t uc, size_t sc) :
		    func(f), analysisTime(t), updateCount(uc), submitCount(sc)
		{}
	};

	/*!
		\ingroup binaryview
	*/
	struct AnalysisInfo
	{
		BNAnalysisState state;
		uint64_t analysisTime;
		std::vector<ActiveAnalysisInfo> activeInfo;
	};


	/*! \c BinaryView implements a view on binary data, and presents a queryable interface of a binary file.

		One key job of BinaryView is file format parsing which allows Binary Ninja to read, write, insert, remove portions
		of the file given a virtual address. For the purposes of this documentation we define a virtual address as the
		memory address that the various pieces of the physical file will be loaded at.

		A binary file does not have to have just one BinaryView, thus much of the interface to manipulate disassembly exists
		within or is accessed through a BinaryView. All files are guaranteed to have at least the \c Raw BinaryView. The
		\c Raw BinaryView is simply a hex editor, but is helpful for manipulating binary files via their absolute addresses.

		BinaryViews are plugins and thus registered with Binary Ninja at startup, and thus should **never** be instantiated
		directly as this is already done. The list of available BinaryViews can be seen in the BinaryViewType class which
		provides an iterator and map of the various installed BinaryViews:

		\code{.cpp}
		// Getting a list of valid BinaryViewTypes
		vector<Ref<BinaryViewType>> types = BinaryViewType::GetViewTypes()

		// Getting a list of valid BinaryViewTypes valid for given data
		vector<Ref<BinaryViewType>> types = BinaryViewType::GetViewTypesForData(bv);

		Ref<BinaryViewType> machoType = BinaryViewType::GetByName("Mach-O");
		\endcode

		\see BinaryViewType

		\b In the python console:
		\code{.py}
		>>> list(BinaryViewType)
		[<view type: 'Raw'>, <view type: 'ELF'>, <view type: 'Mach-O'>, <view type: 'PE'>]
		>>> BinaryViewType['ELF']
		<view type: 'ELF'>
		\endcode

		To open a file with a given BinaryView the following code is recommended:

		\code{.cpp}
		auto bv = Load("/bin/ls");
		\endcode

		\remark By convention in the rest of this document we will use bv to mean an open and, analyzed, BinaryView of an executable file.

		When a BinaryView is open on an executable view analysis is automatically run unless specific named parameters are used
		to disable updates. If such a parameter is used, updates can be triggered using the \c UpdateAnalysisAndWait() method
		which disassembles the executable and returns when all disassembly and analysis is complete:

		\code{.cpp}
		bv->UpdateAnalysisAndWait();
		\endcode

		Since BinaryNinja's analysis is multi-threaded this can also be done in the background
		by using the \c UpdateAnalysis method instead.

		\note An important note on the \c \*User\*() methods. Binary Ninja makes a distinction between edits
		performed by the user and actions performed by auto analysis.  Auto analysis actions that can quickly be recalculated
		are not saved to the database. Auto analysis actions that take a long time and all user edits are stored in the
		database (e.g. \c RemoveUserFunction rather than \c RemoveFunction ). Thus use \c \*User\*() methods if saving
		to the database is desired.

		\ingroup binaryview
	*/
	class BinaryView : public CoreRefCountObject<BNBinaryView, BNNewViewReference, BNFreeBinaryView>
	{
		std::unique_ptr<MemoryMap> m_memoryMap;

	  protected:
		Ref<FileMetadata> m_file;  //!< The underlying file

		/*! BinaryView constructor
		   \param typeName name of the BinaryView (e.g. ELF, PE, Mach-O, ...)
		   \param file a file to create a view from
		   \param parentView optional view that contains the raw data used by this view
		*/
		BinaryView(const std::string& typeName, FileMetadata* file, BinaryView* parentView = nullptr);

		/*! PerformRead provides a mapping between the flat file and virtual offsets in the file.

		    \note This method **may** be overridden by custom BinaryViews. Use AddAutoSegment to provide
		    	  data without overriding this method.

			\warning This method **must not** be called directly.

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

		/*! PerformWrite provides a mapping between the flat file and virtual offsets in the file.

		    \note This method **may** be overridden by custom BinaryViews. Use AddAutoSegment to provide
		          data without overriding this method.

			\warning This method **must not** be called directly.
		    \param offset the virtual offset to find and write len bytes to
		    \param data the address to read len number of bytes from
		    \param len the number of bytes to read from data and write to offset
		    \return length of data written, 0 on error
		*/
		virtual size_t PerformWrite(uint64_t offset, const void* data, size_t len)
		{
			(void)offset;
			(void)data;
			(void)len;
			return 0;
		}

		/*! PerformInsert provides a mapping between the flat file and virtual offsets in the file,
				inserting `len` bytes from `data` to virtual address `offset`

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual offset to find and insert len bytes into
		    \param data the address to read len number of bytes from
		    \param len the number of bytes to read from data and insert at offset
		    \return length of data inserted, 0 on error
		*/
		virtual size_t PerformInsert(uint64_t offset, const void* data, size_t len)
		{
			(void)offset;
			(void)data;
			(void)len;
			return 0;
		}

		/*! PerformRemove provides a mapping between the flat file and virtual offsets in the file,
		    	removing `len` bytes from virtual address `offset`

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

			\param offset the virtual offset to find and remove bytes from
		    \param len the number of bytes to be removed
		    \return length of data removed, 0 on error
		*/
		virtual size_t PerformRemove(uint64_t offset, uint64_t len)
		{
			(void)offset;
			(void)len;
			return 0;
		}

		/*! PerformGetModification implements a query as to whether the virtual address `offset` is modified.

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset a virtual address to be checked
		    \return one of Original, Changed, Inserted
		*/
		virtual BNModificationStatus PerformGetModification(uint64_t offset)
		{
			(void)offset;
			return Original;
		}

		/*! PerformIsValidOffset implements a check as to whether a virtual address `offset` is valid

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is valid
		*/
		virtual bool PerformIsValidOffset(uint64_t offset);

		/*! PerformIsOffsetReadable implements a check as to whether a virtual address is readable

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is readable
		*/
		virtual bool PerformIsOffsetReadable(uint64_t offset);

		/*! PerformIsOffsetWritable implements a check as to whether a virtual address is writable

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is writable
		*/
		virtual bool PerformIsOffsetWritable(uint64_t offset);

		/*! PerformIsOffsetExecutable implements a check as to whether a virtual address is executable

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset the virtual address to check
		    \return whether the offset is executable
		*/
		virtual bool PerformIsOffsetExecutable(uint64_t offset);

		/*! PerformIsOffsetBackedByFile implements a check as to whether a virtual address is backed by a file

		    \param offset the virtual address to check
		    \return whether the offset is backed by a file
		*/
		virtual bool PerformIsOffsetBackedByFile(uint64_t offset);

		/*! PerformGetNextValidOffset implements a query for the next valid readable, writable, or executable virtual memory address after `offset`

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \param offset a virtual address to start checking from
		    \return the next valid address
		*/
		virtual uint64_t PerformGetNextValidOffset(uint64_t offset);

		/*! PerformGetStart implements a query for the first readable, writable, or executable virtual address in the BinaryView

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return the first virtual address in the BinaryView
		*/
		virtual uint64_t PerformGetStart() const { return 0; }
		virtual uint64_t PerformGetLength() const { return 0; }
		virtual uint64_t PerformGetEntryPoint() const { return 0; }

		/*! PerformIsExecutable implements a check which returns true if the BinaryView is executable.

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return whether the BinaryView is executable
		*/
		virtual bool PerformIsExecutable() const { return false; }

		/*! PerformGetDefaultEndianness implements a check which returns the Endianness of the BinaryView

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return either LittleEndian or BigEndian
		*/
		virtual BNEndianness PerformGetDefaultEndianness() const;

		/*! PerformIsRelocatable implements a check which returns true if the BinaryView is relocatable.

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return whether the BinaryView is relocatable
		*/
		virtual bool PerformIsRelocatable() const;

		/*! PerformGetAddressSize implements a query for the address size for this BinaryView

		    \note This method **may** be overridden by custom BinaryViews.

			\warning This method **must not** be called directly.

		    \return the address size for this BinaryView
		*/
		virtual size_t PerformGetAddressSize() const;

		virtual bool PerformSave(FileAccessor* file);
		void PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc);
		void PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> sym, uint64_t reloc);

	  public:
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

		virtual bool Init() { return true; }


		/*!
			\return FileMetadata for this BinaryView
		*/
		FileMetadata* GetFile() const { return m_file; }

		/*!
		    \return View that contains the raw data used by this view
		*/
		Ref<BinaryView> GetParentView() const;
		std::string GetTypeName() const;

		/*!
			\return Whether the file has unsaved modifications
		*/
		bool IsModified() const;

		/*!
			\return Whether auto-analysis results have changed.
		*/
		bool IsAnalysisChanged() const;

		/*! Writes the current database (.bndb) out to the specified file.

		 	\param path path and filename to write the bndb to. Should have ".bndb" appended to it.
		 	\param settings Special save options
		 	\return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& path, Ref<SaveSettings> settings = new SaveSettings());

		/*! Writes the current database (.bndb) out to the specified file.

		    \param path path and filename to write the bndb to. Should have ".bndb" appended to it.
		    \param progressCallback callback function to send save progress to.
		    \param settings Special save options
		    \return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& path,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback,
		    Ref<SaveSettings> settings = new SaveSettings());
		bool SaveAutoSnapshot(Ref<SaveSettings> settings = new SaveSettings());
		bool SaveAutoSnapshot(const std::function<bool(size_t progress, size_t total)>& progressCallback,
		    Ref<SaveSettings> settings = new SaveSettings());

		/*! Run a function in a context in which any changes made to analysis will be added to an undo state.
			If the function returns false or throws an exception, any changes made within will be reverted.

			\param func Function to run in undo context
			\return Return status of function
			\throws std::exception If the called function throws an exception
		 */
		bool RunUndoableTransaction(std::function<bool()> func);

		/*! Start recording actions taken so they can be undone at some point

			\param anonymousAllowed Legacy interop: prevent empty calls to CommitUndoActions from affecting this
			                        undo state. Specifically for RunUndoableTransaction.
			\return Id of UndoEntry created, for passing to either CommitUndoActions or RevertUndoActions
		*/
		[[nodiscard]] std::string BeginUndoActions(bool anonymousAllowed = true);

		/*!  Commit the actions taken since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void CommitUndoActions(const std::string& id);

		/*!  Revert the actions taken since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void RevertUndoActions(const std::string& id);

		/*!  Forget the actions taken since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void ForgetUndoActions(const std::string& id);

		/*!
			\return Whether it is possible to perform an Undo
		*/
		bool CanUndo();

		/*! Undo the last committed action in the undo database.
		*/
		bool Undo();

		/*!
			\return Whether it is possible to perform a Redo
		*/
		bool CanRedo();

		/*! Redo the last committed action in the undo database.
		*/
		bool Redo();

		/*!
		    Get the current View name, e.g. ``Linear:ELF``, ``Graph:PE``

		    \return The current view name
		*/
		std::string GetCurrentView();

		/*!
		    Get the current offset in the current view

		    \return The current offset
		*/
		uint64_t GetCurrentOffset();

		/*!
			Navigate to the specified virtual address in the specified view

		 	\param view View name. e.g. ``Linear:ELF``, ``Graph:PE``
		 	\param offset Virtual address to navigate to
		 	\return Whether the navigation was successful.
		*/
		bool Navigate(const std::string& view, uint64_t offset);

		/*! Read writes `len` bytes at virtual address `offset` to address `dest`

		    \param dest Virtual address to write to
		    \param offset virtual address to read from
		    \param len number of bytes to read
		    \return amount of bytes read
		*/
		size_t Read(void* dest, uint64_t offset, size_t len);

		/*! ReadBuffer reads len bytes from a virtual address into a DataBuffer

		    \param offset virtual address to read from
		    \param len number of bytes to read
		    \return DataBuffer containing the read bytes
		*/
		DataBuffer ReadBuffer(uint64_t offset, size_t len);

		/*! Write writes `len` bytes data at address `dest` to virtual address `offset`

			\param offset virtual address to write to
			\param data address to read from
			\param len number of bytes to write
			\return amount of bytes written
		*/
		size_t Write(uint64_t offset, const void* data, size_t len);

		/*! WriteBuffer writes the contents of a DataBuffer into a virtual address

			\param offset virtual address to write to
		    \param data DataBuffer containing the bytes to write
		    \return amount of bytes written
		*/
		size_t WriteBuffer(uint64_t offset, const DataBuffer& data);

		/*! Insert inserts `len` bytes data at address `dest` starting from virtual address `offset`

			\param offset virtual address to start inserting from
			\param data address to read from
			\param len number of bytes to write
			\return amount of bytes written
		*/
		size_t Insert(uint64_t offset, const void* data, size_t len);

		/*! InsertBuffer inserts the contents of a DataBuffer starting from a virtual address

			\param offset virtual address to start inserting from
		    \param data DataBuffer containing the bytes to write
		    \return amount of bytes written
		*/
		size_t InsertBuffer(uint64_t offset, const DataBuffer& data);

		/*! PerformRemove removes `len` bytes from virtual address `offset`

			\param offset the virtual offset to find and remove bytes from
		    \param len the number of bytes to be removed
		    \return length of data removed, 0 on error
		*/
		size_t Remove(uint64_t offset, uint64_t len);

		std::vector<float> GetEntropy(uint64_t offset, size_t len, size_t blockSize);

		/*! GetModification checks whether the virtual address `offset` is modified.

		    \param offset a virtual address to be checked
		    \return one of Original, Changed, Inserted
		*/
		BNModificationStatus GetModification(uint64_t offset);
		std::vector<BNModificationStatus> GetModification(uint64_t offset, size_t len);

		/*! IsValidOffset checks whether a virtual address `offset` is valid

		    \param offset the virtual address to check
		    \return whether the offset is valid
		*/
		bool IsValidOffset(uint64_t offset) const;

		/*! IsOffsetReadable checks whether a virtual address is readable

		    \param offset the virtual address to check
		    \return whether the offset is readable
		*/
		bool IsOffsetReadable(uint64_t offset) const;

		/*! IsOffsetWritable checks whether a virtual address is writable

		    \param offset the virtual address to check
		    \return whether the offset is writable
		*/
		bool IsOffsetWritable(uint64_t offset) const;

		/*! IsOffsetExecutable checks whether a virtual address is executable

		    \param offset the virtual address to check
		    \return whether the offset is executable
		*/
		bool IsOffsetExecutable(uint64_t offset) const;

		/*! IsOffsetBackedByFile checks whether a virtual address is backed by a file

		    \param offset the virtual address to check
		    \return whether the offset is backed by a file
		*/
		bool IsOffsetBackedByFile(uint64_t offset) const;
		bool IsOffsetCodeSemantics(uint64_t offset) const;
		bool IsOffsetWritableSemantics(uint64_t offset) const;
		bool IsOffsetExternSemantics(uint64_t offset) const;

		/*! GetNextValidOffset implements a query for the next valid readable, writable, or executable virtual memory address after `offset`

		    \param offset a virtual address to start checking from
		    \return the next valid address
		*/
		uint64_t GetNextValidOffset(uint64_t offset) const;

		/*! GetImageBase queries for the image base in the BinaryView

		    \return the image base of the BinaryView
		*/
		uint64_t GetImageBase() const;

		/*! GetOriginalImageBase queries for the original image base in the BinaryView, unaffected by any rebasing operations

		    \return the original image base of the BinaryView
		*/
		uint64_t GetOriginalImageBase() const;

		/*! SetOriginalBase sets the original image base in the BinaryView, unaffected by any rebasing operations.
		 * This is only intended to be used by Binary View implementations to provide this value. Regular users should
		 * NOT change this value.

		    \param imageBase the original image base of the binary view
		*/
		void SetOriginalImageBase(uint64_t imageBase);


		/*! GetOriginalBase queries for the original image base in the BinaryView, unaffected by any rebasing operations
		    \deprecated This API has been deprecated in favor of GetOriginalImageBase in 4.0.xxxx

		    \return the original image base of the BinaryView
		*/
		uint64_t GetOriginalBase() const;

		/*! SetOriginalBase sets the original image base in the BinaryView, unaffected by any rebasing operations.
		 * This is only intended to be used by Binary View implementations to provide this value. Regular users should
		 * NOT change this value.
		    \deprecated This API has been deprecated in favor of SetOriginalImageBase in 4.0.xxxx

		    \param base the original image base of the binary view
		*/
		void SetOriginalBase(uint64_t base);

		/*! GetStart queries for the first valid virtual address in the BinaryView

		    \return the start of the BinaryView
		*/
		uint64_t GetStart() const;

		/*! GetEnd queries for the end virtual address of the BinaryView

		    \return the end of the BinaryView
		*/
		uint64_t GetEnd() const;

		/*! GetLength queries for the total length of the BinaryView from start to end

		    \return the length of the BinaryView
		*/
		uint64_t GetLength() const;

		/*! GetEntryPoint returns the entry point of the executable in the BinaryView
					    \return the entry point
		*/
		uint64_t GetEntryPoint() const;

		/*! GetDefaultArchitecture returns the current "default architecture" for the BinaryView

		    \return the current default architecture
		*/
		Ref<Architecture> GetDefaultArchitecture() const;

		/*! SetDefaultArchitecture allows setting the default architecture for the BinaryView

		    \param arch the new default architecture
		*/
		void SetDefaultArchitecture(Architecture* arch);

		/*! GetDefaultPlatform returns the current default platform for the BinaryView

		    \return the current default Platform
		*/
		Ref<Platform> GetDefaultPlatform() const;

		/*! SetDefaultPlatform allows setting the default platform for the BinaryView

		    \param arch the new default platform
		*/
		void SetDefaultPlatform(Platform* platform);

		/*! GetDefaultEndianness returns the default endianness for the BinaryView

		    \return the current default Endianness, one of LittleEndian, BigEndian
		*/
		BNEndianness GetDefaultEndianness() const;

		/*! Whether the binary is relocatable

		    \return Whether the binary is relocatable
		*/
		bool IsRelocatable() const;

		/*! Address size of the binary

		    \return Address size of the binary
		*/
		size_t GetAddressSize() const;

		/*! Whether the binary is an executable

		    \return Whether the binary is an executable
		*/
		bool IsExecutable() const;

		/*! Save the original binary file to a FileAccessor

		    \param file a FileAccessor pointing to the location to save the binary
		    \return Whether the save was successful
		*/
		bool Save(FileAccessor* file);

		/*! Save the original binary file to the provided destination

		    \param path destination path and filename of the file to be written
		    \return Whether the save was successful
		*/
		bool Save(const std::string& path);

		void DefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc);
		void DefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> target, uint64_t reloc);
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRanges() const;
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRangesAtAddress(uint64_t addr) const;
		std::vector<std::pair<uint64_t, uint64_t>> GetRelocationRangesInRange(uint64_t addr, size_t size) const;
		bool RangeContainsRelocation(uint64_t addr, size_t size) const;
		std::vector<Ref<Relocation>> GetRelocationsAt(uint64_t addr) const;

		/*! Provides a mechanism for receiving callbacks for various analysis events.

		    \param notify An instance of a class Subclassing BinaryDataNotification
		*/
		void RegisterNotification(BinaryDataNotification* notify);

		/*! Unregister a notification passed to RegisterNotification

		    \param notify An instance of a class Subclassing BinaryDataNotification
		*/
		void UnregisterNotification(BinaryDataNotification* notify);

		/*! Adds an analysis option. Analysis options elaborate the analysis phase. The user must start analysis by calling either UpdateAnalysis or UpdateAnalysisAndWait

		    \param name Name of the analysis option. Available options are "linearsweep" and "signaturematcher"
		*/
		void AddAnalysisOption(const std::string& name);

		/*! Add a new function of the given platform at the virtual address

		    \param platform Platform for the function to be loaded
		    \param addr Virtual adddress of the function to be loaded
		    \param autoDiscovered true if function was automatically discovered, false if created by user
		    \param type optional function type
		*/
		Ref<Function> AddFunctionForAnalysis(
			Platform* platform, uint64_t addr, bool autoDiscovered = false, Type* type = nullptr);

		/*! adds an virtual address to start analysis from for a given platform

		    \param platform Platform for the entry point analysis
		    \param start virtual address to start analysis from
		*/
		void AddEntryPointForAnalysis(Platform* platform, uint64_t start);

		/*! adds an function to all entry function list

			\param func Function to add
		*/
		void AddToEntryFunctions(Function* func);

		/*! removes a function from the list of functions

		    \param func Function to be removed
		    \param updateRefs automatically update other functions that were referenced
		*/
		void RemoveAnalysisFunction(Function* func, bool updateRefs = false);

		/*! Add a new user function of the given platform at the virtual address

			\param platform Platform for the function to be loaded
		    \param addr Virtual adddress of the function to be loaded
		*/
		Ref<Function> CreateUserFunction(Platform* platform, uint64_t start);

		/*! removes a user function from the list of functions

		    \param func Function to be removed
		*/
		void RemoveUserFunction(Function* func);

		/*! check for the presence of an initial analysis in this BinaryView.

		    \return Whether the BinaryView has an initial analysis
		*/
		bool HasInitialAnalysis();

		/*! Controls the analysis hold for this BinaryView. Enabling analysis hold defers all future
		 	analysis updates, therefore causing UpdateAnalysis and UpdateAnalysisAndWait to take no action.

		    \param enable Whether to enable or disable the analysis hold
		*/
		void SetAnalysisHold(bool enable);

		/*! start the analysis running and dont return till it is complete

			Analysis of BinaryViews does not occur automatically, the user must start analysis by calling either
		 	UpdateAnalysis or UpdateAnalysisAndWait. An analysis update **must** be run after changes are made which could change
		    analysis results such as adding functions.
		*/
		void UpdateAnalysisAndWait();

		/*! asynchronously starts the analysis running and returns immediately.

			Analysis of BinaryViews does not occur automatically, the user must start analysis by calling either
		 	UpdateAnalysis or UpdateAnalysisAndWait. An analysis update **must** be run after changes are made which could change
		    analysis results such as adding functions.
		*/
		void UpdateAnalysis();

		/*! Abort the currently running analysis

			This method should be considered non-recoverable and generally only used when shutdown is imminent after stopping.
		*/
		void AbortAnalysis();

		/*! Define a DataVariable at a given address with a set type

		    \param addr virtual address to define the DataVariable at
		    \param type Type for the DataVariable
		*/
		void DefineDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type);

		/*! Define a user DataVariable at a given address with a set type

		    \param addr virtual address to define the DataVariable at
		    \param type Type for the DataVariable
		*/
		void DefineUserDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type);

		/*! Undefine a DataVariable at a given address

		    \param addr virtual address of the DataVariable
		*/
		void UndefineDataVariable(uint64_t addr);

		/*! Undefine a user DataVariable at a given address

		    \param addr virtual address of the DataVariable
		*/
		void UndefineUserDataVariable(uint64_t addr);

		/*! Get a map of DataVariables defined in the current BinaryView

		    \return A map of addresses to the DataVariables defined at them
		*/
		std::map<uint64_t, DataVariable> GetDataVariables();

		/*! Get a DataVariable at a given address

		    \param addr Address for the DataVariable
		    \param var Reference to a DataVariable class to write to
		    \return Whether a DataVariable was successfully retrieved
		*/
		bool GetDataVariableAtAddress(uint64_t addr, DataVariable& var);

		/*! Get a list of functions within this BinaryView

		    \return vector of Functions within the BinaryView
		*/
		std::vector<Ref<Function>> GetAnalysisFunctionList();

		/*! Check whether the BinaryView has any functions defined

		    \return Whether the BinaryView has any functions defined
		*/
		bool HasFunctions() const;


		/*! Gets a function object for the function starting at a virtual address

		    \param platform Platform for the desired function
		    \param addr Starting virtual address for the function
		    \return the Function, if it exists
		*/
		Ref<Function> GetAnalysisFunction(Platform* platform, uint64_t addr);

		/*! Get the most recently used Function starting at a virtual address

		    \param addr Starting virtual address for the function
		    \return the Function, if it exists
		*/
		Ref<Function> GetRecentAnalysisFunctionForAddress(uint64_t addr);

		/*! Get a list of functions defined at an address

		    \param addr Starting virtual address for the function
		    \return vector of functions
		*/
		std::vector<Ref<Function>> GetAnalysisFunctionsForAddress(uint64_t addr);

		/*! Get a list of functions containing an address

		    \param addr Address to check
		    \return vector of Functions
		*/
		std::vector<Ref<Function>> GetAnalysisFunctionsContainingAddress(uint64_t addr);

		/*! Get the function defined as the Analysis entry point for the view

		    \return The analysis entry point function
		*/
		Ref<Function> GetAnalysisEntryPoint();

		/*! Get all entry functions (including user-defined ones)

		    \return vector of Functions
		*/
		std::vector<Ref<Function>> GetAllEntryFunctions();

		/*! Get most recently used Basic Block containing a virtual address

		    \param addr Address within the BasicBlock
		    \return The BasicBlock if it exists
		*/
		Ref<BasicBlock> GetRecentBasicBlockForAddress(uint64_t addr);

		/*! Get a list of Basic Blocks containing a virtual address

		    \param addr Address to check
		    \return vector of basic blocks containing that address
		*/
		std::vector<Ref<BasicBlock>> GetBasicBlocksForAddress(uint64_t addr);

		/*! Get a list of basic blocks starting at a virtual address

		    \param addr Address to check
		    \return vector of basic blocks starting at that address
		*/
		std::vector<Ref<BasicBlock>> GetBasicBlocksStartingAtAddress(uint64_t addr);

		/*! Get a list of references made from code (instructions) to a virtual address

		    \param addr Address to check
		    \return vector of ReferenceSources referencing the virtual address
		*/
		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr);

		/*! Get a list of references from code (instructions) to a range of addresses

		    \param addr Address to check
		    \param len Length of query
		    \return vector of ReferenceSources referencing the virtual address range
		*/
		std::vector<ReferenceSource> GetCodeReferences(uint64_t addr, uint64_t len);

		/*! Get code references made by a particular "ReferenceSource"

			A ReferenceSource contains a given function, architecture of that function, and an address within it.

		    \param src reference source
		    \return List of virtual addresses referenced by this source
		*/
		std::vector<uint64_t> GetCodeReferencesFrom(ReferenceSource src);

		/*! Get code references from a range of addresses.

			A ReferenceSource contains a given function, architecture of that function, and an address within it.

			The 2nd parameter is the length of the range. The start of the range is set in ReferenceSource::addr

		    \param src reference source
		    \param len Length of query
		    \return List of virtual addresses referenced by this source
		*/
		std::vector<uint64_t> GetCodeReferencesFrom(ReferenceSource src, uint64_t len);

		/*! Get references made by data ('DataVariables') to a virtual address

		    \param addr Address to check
		    \return vector of virtual addresses referencing the virtual address
		*/
		std::vector<uint64_t> GetDataReferences(uint64_t addr);

		/*! Get references made by data ('DataVariables') in a given range, to a virtual address

		    \param addr Address to check
		    \param len Length of query
		    \return vector of virtual addresses referencing the virtual address range
		*/
		std::vector<uint64_t> GetDataReferences(uint64_t addr, uint64_t len);

		/*! Get references made by data ('DataVariables') located at a virtual address.

		    \param src reference source
		    \return List of virtual addresses referenced by this address
		*/
		std::vector<uint64_t> GetDataReferencesFrom(uint64_t addr);

		/*! Get references made by data ('DataVariables') located in a range of virtual addresses.

		    \param src reference source
		    \param len Length of query
		    \return List of virtual addresses referenced by this address
		*/
		std::vector<uint64_t> GetDataReferencesFrom(uint64_t addr, uint64_t len);

		/*! Add a user Data Reference from a virtual address to another virtual address

		    \param fromAddr Address referencing the toAddr value
		    \param toAddr virtual address being referenced
		*/
		void AddUserDataReference(uint64_t fromAddr, uint64_t toAddr);

		/*! Remove a user Data Reference from a virtual address to another virtual address

		    \param fromAddr Address referencing the toAddr value
		    \param toAddr virtual address being referenced
		*/
		void RemoveUserDataReference(uint64_t fromAddr, uint64_t toAddr);

		// References to type

		/*! Get code references to a Type

		    \param type QualifiedName for a Type
		    \return vector of ReferenceSources
		*/
		std::vector<ReferenceSource> GetCodeReferencesForType(const QualifiedName& type);

		/*! Get data references to a Type

		    \param type QualifiedName for a Type
		    \return vector of virtual addresses referencing this Type
		*/
		std::vector<uint64_t> GetDataReferencesForType(const QualifiedName& type);

		/*! Get Type references to a Type

		    \param type QualifiedName for a Type
		    \return vector of TypeReferenceSources to this Type
		*/
		std::vector<TypeReferenceSource> GetTypeReferencesForType(const QualifiedName& type);

		/*! Returns a list of references to a specific type field

			\param type QualifiedName of the type
			\param offset Offset of the field, relative to the start of the type
			\return vector of TypeFieldReferences
		*/
		std::vector<TypeFieldReference> GetCodeReferencesForTypeField(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of virtual addresses of data which references the type \c type .

			Note, the returned addresses are the actual start of the queried type field. For example, suppose there is a
			DataVariable at \c 0x1000 that has type \c A , and type \c A contains type \c B at offset \c 0x10 .
			Then <tt>GetDataReferencesForTypeField(bQualifiedName, 0x8)</tt> will return \c 0x1018 for it.

			\param type QualifiedName of the type
			\param offset Offset of the field, relative to the start of the type
			\return List of DataVariable start addresses containing references to the type field
		*/
		std::vector<uint64_t> GetDataReferencesForTypeField(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of virtual addresses of data which are referenced from the type \c type .

		    Only data referenced by structures with the \c __data_var_refs attribute are included.

		    \param type QualifiedName of the type
		    \param offset Offset of the field, relative to the start of the type
		    \return List of addresses referenced from the type field
		*/
		std::vector<uint64_t> GetDataReferencesFromForTypeField(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of type references to a specific type field

			\param type QualifiedName of the type
			\param offset Offset of the field, relative to the start of the type
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetTypeReferencesForTypeField(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of types referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source of the reference to check
		 	\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFrom(ReferenceSource src);

		/*! Returns a list of types referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source location to check
			\param len Length of the query
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFrom(ReferenceSource src, uint64_t len);

		/*! Returns a list of type fields referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source location to check
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFieldFrom(ReferenceSource src);

		/*! Returns a list of type fields referenced by code at ReferenceSource \c src

			If no function is specified, references from all functions and containing the address will be returned.
		 	If no architecture is specified, the architecture of the function will be used.

			\param src Source location to check
			\param len Length of the query
			\return vector of TypeReferenceSources
		*/
		std::vector<TypeReferenceSource> GetCodeReferencesForTypeFieldFrom(ReferenceSource src, uint64_t len);

		/*! Returns a list of offsets in the QualifiedName specified by name, which are referenced by code.

			\param type Name of type to query for references
			\return List of offsets
		*/
		std::vector<uint64_t> GetAllFieldsReferenced(const QualifiedName& type);

		/*! Returns a map from field offset to a list of sizes of the accesses to the specified type.

			\param type Name of type to query for references
			\return A map from field offset to the	size of the code accesses to it
		*/
		std::map<uint64_t, std::vector<size_t>> GetAllSizesReferenced(const QualifiedName& type);

		/*! Returns a map from field offset to a list of incoming types written to the specified type.

			\param type Name of type to query for references
			\return A map from field offset to a list of incoming types written to it
		*/
		std::map<uint64_t, std::vector<Confidence<Ref<Type>>>> GetAllTypesReferenced(const QualifiedName& type);

		/*! Returns a list of types related to the type field access.

			\param type Name of type to query for references
			\param offset Offset of the field, relative to the start of the type
			\return A list of sizes of accesses to the type
		*/
		std::vector<size_t> GetSizesReferenced(const QualifiedName& type, uint64_t offset);

		/*! Returns a list of types referenced by a particular type field

			\param type Name of type to query for references
			\param offset Offset of the field, relative to the start of the type
			\return A list of types referenced
		*/
		std::vector<Confidence<Ref<Type>>> GetTypesReferenced(const QualifiedName& type, uint64_t offset);

		std::unordered_set<QualifiedName> GetOutgoingDirectTypeReferences(const QualifiedName& type);
		std::unordered_set<QualifiedName> GetOutgoingRecursiveTypeReferences(const QualifiedName& type);
		std::unordered_set<QualifiedName> GetOutgoingRecursiveTypeReferences(const std::unordered_set<QualifiedName>& types);
		std::unordered_set<QualifiedName> GetIncomingDirectTypeReferences(const QualifiedName& type);
		std::unordered_set<QualifiedName> GetIncomingRecursiveTypeReferences(const QualifiedName& type);
		std::unordered_set<QualifiedName> GetIncomingRecursiveTypeReferences(const std::unordered_set<QualifiedName>& types);

		Ref<Structure> CreateStructureBasedOnFieldAccesses(const QualifiedName& type); // Unimplemented!

		/*! Returns a list of virtual addresses called by the call site in the ReferenceSource

			If no function is specified, call sites from
			all functions and containing the address will be considered. If no architecture is specified, the
			architecture of the function will be used.

			\param addr ReferenceSource to get callees to
			\return A list of addresses referencing the ReferenceSource
		*/
		std::vector<uint64_t> GetCallees(ReferenceSource addr);

		/*! Returns a list of ReferenceSource objects (xrefs or cross-references) that call the provided virtual address

			In this case, tail calls, jumps, and ordinary calls are considered.

			\param addr Address to check callers for
			\return A list of ReferenceSources calling this address
		*/
		std::vector<ReferenceSource> GetCallers(uint64_t addr);

		/*! Returns the Symbol at the provided virtual address

			\param addr Virtual address to query for symbol
			\param nameSpace The optional namespace of the symbols to retrieve
			\return The symbol located at that address
		*/
		Ref<Symbol> GetSymbolByAddress(uint64_t addr, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a Symbol object for the given a raw (mangled) name.

			\param name Raw (mangled) name of the symbol
			\param nameSpace The optional namespace of the symbols to retrieve
			\return The symbol with that raw name
		*/
		Ref<Symbol> GetSymbolByRawName(const std::string& name, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of symbols with a given name

			\param name Name to search for
			\param nameSpace The optional namespace of the symbols to retrieve
			\return List of symbols with that name
		*/
		std::vector<Ref<Symbol>> GetSymbolsByName(const std::string& name, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves the list of all Symbol objects with a given raw name

			\param name RawName to search for
			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols
		*/
		std::vector<Ref<Symbol>> GetSymbolsByRawName(const std::string& name, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves the list of all Symbol objects

			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols
		*/
		std::vector<Ref<Symbol>> GetSymbols(const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of symbols in a given range

			\param start Virtual address start of the range
			\param len Length of the range
			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols for a given type
		*/
		std::vector<Ref<Symbol>> GetSymbols(uint64_t start, uint64_t len, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of all Symbol objects of the provided symbol type

			\param type The symbol type
			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols for a given type
		*/
		std::vector<Ref<Symbol>> GetSymbolsOfType(BNSymbolType type, const NameSpace& nameSpace = NameSpace());

		/*! Retrieves a list of all Symbol objects of the provided symbol type in the given range

			\param type The symbol type
			\param start Virtual address start of the range
			\param len Length of the range
			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of symbols for a given type in the given range
		*/
		std::vector<Ref<Symbol>> GetSymbolsOfType(
		    BNSymbolType type, uint64_t start, uint64_t len, const NameSpace& nameSpace = NameSpace());

		/*! Get the list of visible symbols

			\param nameSpace The optional namespace of the symbols to retrieve
			\return A list of visible symbols
		*/
		std::vector<Ref<Symbol>> GetVisibleSymbols(const NameSpace& nameSpace = NameSpace());

		/*! Adds a symbol to the internal list of automatically discovered Symbol objects in a given namespace

			\warning If multiple symbols for the same address are defined, only the most recent symbol will ever be used.

			\param sym Symbol to define
		*/
		void DefineAutoSymbol(Ref<Symbol> sym);

		/*! Defines an "Auto" symbol, and a Variable/Function alongside it

			\param platform Platform for the Type being defined
			\param sym Symbol being definedd
			\param type Type being defined
			\return The defined symbol
		*/
		Ref<Symbol> DefineAutoSymbolAndVariableOrFunction(Ref<Platform> platform, Ref<Symbol> sym, Ref<Type> type);

		/*! Undefine an automatically defined symbol

			\param sym The symbol to undefine
		*/
		void UndefineAutoSymbol(Ref<Symbol> sym);

		/*! Define a user symbol

			\param sym Symbol to define
		*/
		void DefineUserSymbol(Ref<Symbol> sym);

		/*! Undefine a user symbol

			\param sym Symbol to undefinee
		*/
		void UndefineUserSymbol(Ref<Symbol> sym);

		/*! Defines an imported Function \c func with a ImportedFunctionSymbol type

			\param importAddressSym Symbol for the imported function
			\param func Function to define as an imported function
			\param type Optional type for the function
		*/
		void DefineImportedFunction(Ref<Symbol> importAddressSym, Ref<Function> func, Ref<Type> type = nullptr);

		/*! The current debug info object for this binary view

			\return The current debug info object for this binary view
		*/
		Ref<DebugInfo> GetDebugInfo();

		/*! Sets the debug info and applies its contents to the current BinaryView

			\param newDebugInfo
		*/
		void ApplyDebugInfo(Ref<DebugInfo> newDebugInfo);

		/*! Sets the debug info for the current binary view

			\param newDebugInfo Sets the debug info for the current binary view
		*/
		void SetDebugInfo(Ref<DebugInfo> newDebugInfo);

		/*! Determine is a debug info object is currently being applied

			\return True if a debug info object is currently being applied
		*/
		bool IsApplyingDebugInfo() const;

		void BeginBulkModifySymbols();
		void EndBulkModifySymbols();

		/*! Add a new TagType to this binaryview

			\param tagType TagType to add
		*/
		void AddTagType(Ref<TagType> tagType);

		/*! Remove a TagType from this binaryview

			\param tagType TagType to remove
		*/
		void RemoveTagType(Ref<TagType> tagType);

		/*! Get a TagType by name

			\param name Name of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagType(const std::string& name);

		/*! Get a TagType by name and TagType::Type

			\param name Name of the TagType
			\param type Type of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagType(const std::string& name, TagType::Type type);

		/*! Get a TagType by name

			\param name Name of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeByName(const std::string& name);

		/*! Get a TagType by name and TagType::Type

			\param name Name of the TagType
			\param type Type of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeByName(const std::string& name, TagType::Type type);

		/*! Get a TagType by its ID

			\param id ID of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeById(const std::string& id);

		/*! Get a TagType by its ID and TagType::Type

			\param id ID of the TagType
			\param type Type of the TagType
			\return The TagType, if it was found
		*/
		Ref<TagType> GetTagTypeById(const std::string& id, TagType::Type type);

		/*! Get the list of all defined TagTypes

			\return Get the list of all defined TagTypes
		*/
		std::vector<Ref<TagType>> GetTagTypes();

		/*! Add a Tag

			\param tag The tag to add
			\param user Whether this was added by a user or automatically by analysis
		*/
		void AddTag(Ref<Tag> tag, bool user = false);

		/*! Remove a tag

			\param tag The tag to remove
			\param user Whether the tag being removed is a user tag
		*/
		void RemoveTag(Ref<Tag> tag, bool user = false);

		/*! Get a tag by its ID

			\param tagId the tag ID
			\return The tag, if it was found
		*/
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

		/*! Lookup a component by its GUID

			\param guid GUID of the component to look up
			\return The component with that GUID
		*/
		std::optional<Ref<Component>> GetComponentByGuid(std::string guid);

		/*! Lookup a component by its pathname

			\note This is a convenience method, and for performance-sensitive lookups, GetComponentByGuid is very
		 	highly recommended.

		 	\see GetComponentByGuid, Component::GetGuid

			All lookups are absolute from the root component, and are case-sensitive. Pathnames are delimited with "/"

		 	Lookups are done using the display name of the component, which is liable to change when it or its siblings
		 	are moved around.

		 	\see Component::GetDisplayName

			\param path Path of the desired component
			\return The component at that path
		*/
		std::optional<Ref<Component>> GetComponentByPath(std::string path);

		/*! Get the root component for the BinaryView (read-only)

			This Component cannot be removed, and houses all unparented Components.

			\return The Root Component
		*/
		Ref<Component> GetRootComponent();

		/*! Create a component

			This component will be added to the root component and initialized with the name "Component"

			\return The created Component
		*/
		Ref<Component> CreateComponent();

		/*! Create a component as a subcomponent of the component with a given Guid

			This component will be initialized with the name "Component"

			\param parentGUID Guid of the component this component will be added to
			\return The created Component
		*/
		Ref<Component> CreateComponent(std::string parentGUID);

		/*! Create a component as a subcomponent of a given Component

		    This component will be initialized with the name "Component"

		 	\param parent Parent Component
		 	\return The created Component
		*/
		Ref<Component> CreateComponent(Ref<Component> parent);

		/*! Create a component with a given name and optional parent

		    \param name Name to initialize the component with
		    \param parentGUID Optional Guid of the component this component will be added to
		    \return The created Component
		*/
		Ref<Component> CreateComponentWithName(std::string name, std::string parentGUID = {});

		/*! Create a component with a given name and parent

		    \param name Name to initialize the component with
		    \param parentGUID Guid of the component this component will be added to
		    \return The created Component
		*/
		Ref<Component> CreateComponentWithName(std::string name, Ref<Component> parent);

		/*! Remove a component from the tree entirely. This will also by nature remove all subcomponents.

			\param component Component to remove
			\return Whether removal was successful
		*/
		bool RemoveComponent(Ref<Component> component);

		/*! Remove a component from the tree entirely. This will also by nature remove all subcomponents.

			\param guid Guid of the Component to remove
			\return Whether removal was successful
		*/
		bool RemoveComponent(std::string guid);

		std::vector<Ref<Component>> GetFunctionParentComponents(Ref<Function> function) const;
		std::vector<Ref<Component>> GetDataVariableParentComponents(DataVariable var) const;

		/*! Heuristically determine if a string exists at the given address. This API checks for the following settings:
			"analysis.unicode.utf8" - default true enables UTF-8 string detection
			"analysis.unicode.utf16" - default true enables UTF-16 string detection
			"analysis.unicode.utf32" - default true enables UTF-32 string detection
			"analysis.unicode.blocks" - selects the Unicode blocks to use for detection

			\param addr Address to check
			\param value String value to populate
			\param allowShortStrings Whether to allow short strings < 4 characters
			\param allowLargeStrings If false strings must be less than "rendering.strings.maxAnnotationLength" (default 32)
				If true strings must be less than "analysis.limits.maxStringLength" (default 16384)
			\param childWidth Width of the characters
			\return The type of string annotation found

		*/
		std::optional<BNStringType> CheckForStringAnnotationType(uint64_t addr, std::string& value,
			bool allowShortStrings, bool allowLargeStrings, size_t childWidth);

		/*! Check whether the given architecture supports assembling instructions

			\param arch Architecture to check
			\return Whether the given architecture supports assembling instructions
		*/
		bool CanAssemble(Architecture* arch);

		/*! Check whether the "Never Branch" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Never Branch" patch is available
		*/
		bool IsNeverBranchPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Always Branch" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Always Branch" patch is available
		*/
		bool IsAlwaysBranchPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Invert Branch" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Invert Branch" patch is available
		*/
		bool IsInvertBranchPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Skip and Return Zero" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Skip and Return Zero" patch is available
		*/
		bool IsSkipAndReturnZeroPatchAvailable(Architecture* arch, uint64_t addr);

		/*! Check whether the "Skip and Return Value" patch is available for a given architecture at a given address

			\param arch Architecture to check
			\param addr Address of the instruction to be patched
			\return Whether the "Skip and Return Value" patch is available
		*/
		bool IsSkipAndReturnValuePatchAvailable(Architecture* arch, uint64_t addr);

		/*! Convert the instruction at the given address to a nop

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\return Whether the patch was successful
		*/
		bool ConvertToNop(Architecture* arch, uint64_t addr);

		/*! Convert the conditional branch at the given address to always branch

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\return Whether the patch was successful
		*/
		bool AlwaysBranch(Architecture* arch, uint64_t addr);

		/*! Convert the conditional branch at the given address to branch under inverted conditions

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\return Whether the patch was successful
		*/
		bool InvertBranch(Architecture* arch, uint64_t addr);

		/*! Convert the given instruction to skip the rest of the function and return 0

			\param arch Architecture of the instruction to convert
			\param addr Address of the instruction to be patched
			\param value Value to return
			\return Whether the patch was successful
		*/
		bool SkipAndReturnValue(Architecture* arch, uint64_t addr, uint64_t value);

		/*! Get the length of the instruction at a given address

			\param arch Architecture of the instruction
			\param addr Address of the start of the instruction
			\return The length of the instruction
		*/
		size_t GetInstructionLength(Architecture* arch, uint64_t addr);

		/*! Get the string at an address

			\param[in] addr Address of the string
			\param[out] strRef Reference to a StringReference the string reference will be writen to.
			\return Whether a string was at th given address
		*/
		bool GetStringAtAddress(uint64_t addr, BNStringReference& strRef);

		/*! Get the list of strings located within the view

			\return The list of strings
		*/
		std::vector<BNStringReference> GetStrings();

		/*! Get the list of strings located within a range

			\param start Starting virtual address of the range
			\param len Length of the range
			\return The list of strings
		*/
		std::vector<BNStringReference> GetStrings(uint64_t start, uint64_t len);

		/*! Sets up a call back function to be called when analysis has been completed.

			This is helpful when using `UpdateAnalysis` which does not wait for analysis completion before returning.

			The callee of this function is not responsible for maintaining the lifetime of the returned AnalysisCompletionEvent object

			\param callback A function to be called with no parameters when analysis has completed.
			\return An initialized AnalysisCompletionEvent object.
		*/
		Ref<AnalysisCompletionEvent> AddAnalysisCompletionEvent(const std::function<void()>& callback);

		AnalysisInfo GetAnalysisInfo();
		BNAnalysisProgress GetAnalysisProgress();
		Ref<BackgroundTask> GetBackgroundAnalysisTask();

		/*! Returns the virtual address of the Function that occurs after the virtual address `addr`

			\param addr Address to start searching
			\return Next function start
		*/
		uint64_t GetNextFunctionStartAfterAddress(uint64_t addr);

		/*! Returns the virtual address of the BasicBlock that occurs after the virtual address `addr`

			\param addr Address to start searching
			\return Next basic block start
		*/
		uint64_t GetNextBasicBlockStartAfterAddress(uint64_t addr);

		/*! Retrieves the virtual address of the next non-code byte.

			\param addr Address to start searching
			\return address of the next non-code byte
		*/
		uint64_t GetNextDataAfterAddress(uint64_t addr);

		/*! Retrieves the address of the next DataVariable.

			\param addr Address to start searching
			\return address of the next DataVariable
		*/
		uint64_t GetNextDataVariableStartAfterAddress(uint64_t addr);

		/*! Returns the virtual address of the Function that occurs prior to the
			virtual address provided

			\param addr Address to start searching
			\return the virtual address of the previous Function
		*/
		uint64_t GetPreviousFunctionStartBeforeAddress(uint64_t addr);

		/*! Returns the virtual address of the Basic Block that occurs prior to the
			virtual address provided

			\param addr Address to start searching
			\return The virtual address of the previous Basic Block
		*/
		uint64_t GetPreviousBasicBlockStartBeforeAddress(uint64_t addr);

		/*! Returns the ending virtual address of the Basic Block that occurs prior to the
			virtual address provided

			\param addr Address to start searching
			\return The ending virtual address of the previous Basic Block
		*/
		uint64_t GetPreviousBasicBlockEndBeforeAddress(uint64_t addr);

		/*! Returns the virtual address of the previous data (non-code) byte

			\param addr Address to start searching
			\return The virtual address of the previous non-code byte
		*/
		uint64_t GetPreviousDataBeforeAddress(uint64_t addr);

		/*! Returns the virtual address of the previous DataVariable

			\param addr Address to start searching
			\return The virtual address of the previous DataVariable
		*/
		uint64_t GetPreviousDataVariableStartBeforeAddress(uint64_t addr);

		bool ParsePossibleValueSet(const std::string& value, BNRegisterValueType state, PossibleValueSet& result,
		    uint64_t here, std::string& errors);

		/*! Parse a single type and name from a string containing their definition

			\param[in] text Text containing the type definition
			\param[out] result Reference into which the resulting type and name will be written
			\param[out] errors Reference to a list into which any parse errors will be written
			\param[in] typesAllowRedefinition List of types whose names are allowed to be overwritten (legacy cruft?)
			\param[in] importDependencies If Type Library / Type Archive types should be imported during parsing
			\return Whether parsing was successful
		*/
		bool ParseTypeString(const std::string& text, QualifiedNameAndType& result, std::string& errors,
		    const std::set<QualifiedName>& typesAllowRedefinition = {}, bool importDependencies = true);

		/*! Parse an entire block of source into types, variables, and functions

			\param[in] text Source code to parse
			\param[out] types Reference to a map of QualifiedNames and Types the parsed types will be writen to
			\param[out] variables Reference to a list of QualifiedNames and Types the parsed variables will be writen to
			\param[out] functions Reference to a list of QualifiedNames and Types the parsed functions will be writen to
			\param[out] errors Reference to a list into which any parse errors will be written
			\param[in] typesAllowRedefinition List of types whose names are allowed to be overwritten (legacy cruft?)
			\param[in] importDependencies If Type Library / Type Archive types should be imported during parsing
			\return Whether parsing was successful
		*/
		bool ParseTypeString(const std::string& text, std::map<QualifiedName, Ref<Type>>& types,
		    std::map<QualifiedName, Ref<Type>>& variables, std::map<QualifiedName, Ref<Type>>& functions,
		    std::string& errors, const std::set<QualifiedName>& typesAllowRedefinition = {}, bool importDependencies = true);

		/*! Parse an entire block of source into a structure containing types, variables, and functions

			\param[in] text Source code to parse
			\param[out] result Reference to a TypeParserResult structure into which types, variables, and functions will be written
			\param[out] errors Reference to a list into which any parse errors will be written
			\param[in] typesAllowRedefinition List of types whose names are allowed to be overwritten (legacy cruft?)
			\param[in] importDependencies If Type Library / Type Archive types should be imported during parsing
			\return Whether parsing was successful
		*/
		bool ParseTypesFromSource(const std::string& text, const std::vector<std::string>& options, const std::vector<std::string>& includeDirs, TypeParserResult& result,
		    std::string& errors, const std::set<QualifiedName>& typesAllowRedefinition = {}, bool importDependencies = true);

		/*! Type Container for all types (user and auto) in the BinaryView. Any auto types
			modified through the Type Container will be converted into user types.
			\return Full view Type Container
		 */
		class TypeContainer GetTypeContainer();

		/*! Type Container for ONLY auto types in the BinaryView. Any changes to types will
			NOT promote auto types to user types.
			\return Auto types only Type Container
		 */
		class TypeContainer GetAutoTypeContainer();

		/*! Type Container for ONLY user types in the BinaryView.
			\return User types only Type Container
		 */
		class TypeContainer GetUserTypeContainer();

		std::map<QualifiedName, Ref<Type>> GetTypes();
		/*! List of all types, sorted such that types are after all types on which they depend

			Order is guaranteed for any collection of types with no cycles. If you have cycles
			in type dependencies, order for types in a cycle is not guaranteed.

			\note Dependency order is based on named type references for all non-structure types, i.e.
			``struct Foo m_foo`` will induce a dependency, whereas ``struct Foo* m_pFoo`` will not.

			\return Sorted types as defined above
		*/
		std::vector<std::pair<QualifiedName, Ref<Type>>> GetDependencySortedTypes();
		std::vector<QualifiedName> GetTypeNames(const std::string& matching = "");
		Ref<Type> GetTypeByName(const QualifiedName& name);
		Ref<Type> GetTypeByRef(Ref<NamedTypeReference> name);
		Ref<Type> GetTypeById(const std::string& id);
		std::string GetTypeId(const QualifiedName& name);
		QualifiedName GetTypeNameById(const std::string& id);
		bool IsTypeAutoDefined(const QualifiedName& name);
		QualifiedName DefineType(const std::string& id, const QualifiedName& defaultName, Ref<Type> type);
		std::unordered_map<std::string, QualifiedName> DefineTypes(const std::vector<std::pair<std::string, QualifiedNameAndType>>& types, std::function<bool(size_t, size_t)> progress = {});
		void DefineUserType(const QualifiedName& name, Ref<Type> type);
		void DefineUserTypes(const std::vector<QualifiedNameAndType>& types, std::function<bool(size_t, size_t)> progress = {});
		void DefineUserTypes(const std::vector<ParsedType>& types, std::function<bool(size_t, size_t)> progress = {});
		void UndefineType(const std::string& id);
		void UndefineUserType(const QualifiedName& name);
		void RenameType(const QualifiedName& oldName, const QualifiedName& newName);

		void RegisterPlatformTypes(Platform* platform);

		/*! Gives you details of which platform and name was imported to result in the given type name.

			\param name Name of type in the binary view
			\return A pair with the platform and the name of the type in the platform,
			        or std::nullopt if it was not imported
		*/
		std::optional<std::pair<Ref<Platform>, QualifiedName>> LookupImportedTypePlatform(const QualifiedName& name);

		/*! Make the contents of a type library available for type/import resolution

			\param lib library to register with the view
		*/
		void AddTypeLibrary(TypeLibrary* lib);
		/*! Get the type library with the given name

			\param name Library name to lookup
			\return The Type Library object, or nullptr if one has not been added with this name
		*/
		Ref<TypeLibrary> GetTypeLibrary(const std::string& name);
		/*! Get the list of imported type libraries

			\return All imported type libraries
		*/
		std::vector<Ref<TypeLibrary>> GetTypeLibraries();

		/*! Recursively imports a type from the specified type library, or, if no library was explicitly provided,
			the first type library associated with the current `BinaryView` that provides the name requested.

			This may have the impact of loading other type libraries as dependencies on other type libraries are lazily resolved
			when references to types provided by them are first encountered.

			Note that the name actually inserted into the view may not match the name as it exists in the type library in
			the event of a name conflict. To aid in this, the `Type` object returned is a `NamedTypeReference` to
			the deconflicted name used.

			\param lib
			\param name
			\return A `NamedTypeReference` to the type, taking into account any renaming performed
		*/
		Ref<Type> ImportTypeLibraryType(Ref<TypeLibrary>& lib, const QualifiedName& name);
		/*! Recursively imports an object from the specified type library, or, if no library was explicitly provided,
			the first type library associated with the current `BinaryView` that provides the name requested.

			This may have the impact of loading other type libraries as dependencies on other type libraries are lazily resolved
			when references to types provided by them are first encountered.

			.. note:: If you are implementing a custom BinaryView and use this method to import object types,
			you should then call ``RecordImportedObjectLibrary`` with the details of where the object is located.

			\param lib
			\param name
			\return The object type, with any interior `NamedTypeReferences` renamed as necessary to be appropriate for the current view
		*/
		Ref<Type> ImportTypeLibraryObject(Ref<TypeLibrary>& lib, const QualifiedName& name);


		/*! Recursively imports a type by guid from the current BinaryView's set of type libraries

			This API is dependent on the set of TypeLibraries for the current BinaryView's Platform,
			having appropriate metadata to resolve the type by guid. The key "type_guids" must contain
			a map(string(guid), string(type_name)) or
			  map(string(guid), tuple(sting(type_name), string(library_name))).

			\param guid
			\return The type, or nullptr if it was not found

		*/
		Ref<Type> ImportTypeLibraryTypeByGuid(const std::string& guid);


		/* Looks up the name of a type by its guid in the current BinaryView's set of type libraries

			\param guid
			\return The QualifedName of the type or std::nullopt if it was not found
		 */
		std::optional<QualifiedName> GetTypeNameByGuid(const std::string& guid);

		/*! Recursively exports ``type`` into ``lib`` as a type with name ``name``

			As other referenced types are encountered, they are either copied into the destination type library or
			else the type library that provided the referenced type is added as a dependency for the destination library.

			\param lib
			\param name
			\param type
		*/
		void ExportTypeToTypeLibrary(TypeLibrary* lib, const QualifiedName& name, Type* type);
		/*! Recursively exports ``type`` into ``lib`` as an object with name ``name``

			As other referenced types are encountered, they are either copied into the destination type library or
			else the type library that provided the referenced type is added as a dependency for the destination library.

			\param lib
			\param name
			\param type
		*/
		void ExportObjectToTypeLibrary(TypeLibrary* lib, const QualifiedName& name, Type* type);

		/*! Should be called by custom `BinaryView` implementations when they have successfully imported an object
			from a type library (eg a symbol's type). Values recorded with this function will then be queryable via ``LookupImportedObjectLibrary``.

			\param tgtPlatform Platform of symbol at import site
			\param tgtAddr Address of symbol at import site
			\param lib Type Library containing the imported type
			\param name Name of the object in the type library
		*/
		void RecordImportedObjectLibrary(Platform* tgtPlatform, uint64_t tgtAddr, TypeLibrary* lib, const QualifiedName& name);
		/*! Gives you details of which type library and name was used to determine the type of a symbol at a given address.

			\param tgtPlatform Platform of symbol at import site
			\param tgtAddr Address of symbol at import site
			\return A pair with the library and name used, or std::nullopt if it was not imported
		*/
		std::optional<std::pair<Ref<TypeLibrary>, QualifiedName>> LookupImportedObjectLibrary(Platform* tgtPlatform, uint64_t tgtAddr);

		/*! Gives you details of which type library and name was imported to result in the given type name.

			\param name Name of type in the binary view
			\return A pair with the library and the name of the type in the library,
			        or std::nullopt if it was not imported
		 */
		std::optional<std::pair<Ref<TypeLibrary>, QualifiedName>> LookupImportedTypeLibrary(const QualifiedName& name);
		/*! Attach a given type archive to the binary view. No types will actually be associated by calling this, just they
			will become available.

			\param id Expected id of archive
			\param path Path to archive
		 */
		Ref<TypeArchive> AttachTypeArchive(const std::string& id, const std::string& path);
		/*! Detach from a type archive, breaking all associations to types with the archive

			\param id Id of archive to detach
		 */
		void DetachTypeArchive(const std::string& id);
		/*! Look up a connected archive by its id

			\param id Id of archive
			\return Archive, if one exists with that id. Otherwise nullptr
		 */
		Ref<TypeArchive> GetTypeArchive(const std::string& id) const;
		/*! Get all attached type archives

			\return All attached archive (id, path) pairs
		 */
		std::unordered_map<std::string, std::string> GetTypeArchives() const;
		/*! Look up the path for an attached (but not necessarily connected) type archive by its id

			\param id Id of archive
			\return Archive path, if it is attached. Otherwise nullopt.
		 */
		std::optional<std::string> GetTypeArchivePath(const std::string& id) const;
		/*! Get a list of all available type names in all connected archives, and their archive/type id pair

			\return All type names in a map
		 */
		std::unordered_map<QualifiedName, std::map<std::string, std::string>> GetTypeArchiveTypeNames() const;

		/*! Get a list of all types in the analysis that are associated with a specific type archive

			\return Map of all analysis types to their corresponding archive id
		 */
		std::unordered_map<std::string, std::pair<std::string, std::string>> GetAssociatedTypeArchiveTypes() const;
		/*! Get a list of all types in the analysis that are associated with a specific type archive

		    \return Map of all analysis types to their corresponding archive id
		 */
		std::unordered_map<std::string, std::string> GetAssociatedTypesFromArchive(const std::string& archive) const;
		/*! Determine the target archive / type id of a given analysis type

		    \param id Id of analysis type
		    \return Pair of archive id and archive type id, if this type is associated. std::nullopt otherwise.
		 */
		std::optional<std::pair<std::string, std::string>> GetAssociatedTypeArchiveTypeTarget(const std::string& id) const;
		/*! Determine the local source type for a given archive type

		    \param archiveId Id of target archive
		    \param archiveTypeId Id of target archive type
		    \return Id of source analysis type, if this type is associated. std::nullopt otherwise.
		 */
		std::optional<std::string> GetAssociatedTypeArchiveTypeSource(const std::string& archiveId, const std::string& archiveTypeId) const;
		/*! Get the current status of any changes pending in a given type

		    \param id Id of type in analysis
		    \return Status of type
		 */
		BNSyncStatus GetTypeArchiveSyncStatus(const std::string& typeId) const;
		/*! Disassociate an associated type, so that it will no longer receive updates from its connected type archive

		    \param typeId Id of type in analysis
		    \return True if successful
		 */
		bool DisassociateTypeArchiveType(const std::string& typeId);
		/*! Pull a collection of types from a type archive, associating with them and any dependencies

			\param[in] archiveId Id of archive
			\param[in] archiveTypeIds Ids of desired types
			\param[out] updatedTypes List of types that were updated
			\return True if successful
		 */
		bool PullTypeArchiveTypes(const std::string& archiveId, const std::unordered_set<std::string>& archiveTypeIds, std::unordered_map<std::string, std::string>& updatedTypes);
		/*! Push a collection of types, and all their dependencies, into a type archive

			\param[in] archiveId Id of archive
			\param[in] typeIds List of ids of types in analysis
			\param[out] updatedTypes List of types that were updated
			\return True if successful
		 */
		bool PushTypeArchiveTypes(const std::string& archiveId, const std::unordered_set<std::string>& typeIds, std::unordered_map<std::string, std::string>& updatedTypes);

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

		bool Search(const std::string& query, const std::function<bool(uint64_t offset, const DataBuffer& buffer)>& otherCallback);

		void Reanalyze();

		Ref<Workflow> GetWorkflow() const;

		/*! Displays contents to the user in the UI or on the command-line

			\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
			the command line, a simple text prompt is used.

			\param title Title for the report
			\param contents Contents of the report
		*/
		void ShowPlainTextReport(const std::string& title, const std::string& contents);

		/*! Displays markdown contents to the user in the UI or on the command-line

			\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
			the command line, a simple text prompt is used.

			\param title Title for the report
			\param contents Markdown contents of the report
			\param plainText Plaintext contents of the report (used on the command line)
		*/
		void ShowMarkdownReport(const std::string& title, const std::string& contents, const std::string& plainText);

		/*! Displays HTML contents to the user in the UI or on the command-line

			\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
			the command line, a simple text prompt is used.

			\param title Title for the report
			\param contents HTML contents of the report
			\param plainText Plaintext contents of the report (used on the command line)
		*/
		void ShowHTMLReport(const std::string& title, const std::string& contents, const std::string& plainText);

		/*! Displays a flow graph in UI applications and nothing in command-line applications.

			\note This API has no effect outside of the UI

			\param title Title for the report
			\param graph FlowGraph object to be rendered.
		*/
		void ShowGraphReport(const std::string& title, FlowGraph* graph);

		/*! Prompts the user to input an unsigned integer with the given prompt and title

			\param[out] result Reference to the uint64_t the result will be copied to
			\param[in] prompt Prompt for the input
			\param[in] title Title for the input popup when used in UI
			\return Whether an integer was successfully received
		*/
		bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);

		/*! Prompts the user to input an unsigned integer with the given prompt and title

			\param[out] result Reference to the uint64_t the result will be copied to
			\param[in] prompt Prompt for the input
			\param[in] title Title for the input popup when used in UI
		 	\param[in] currentAddress Address to use for relative inputs
			\return Whether an integer was successfully received
		*/
		bool GetAddressInput(
		    uint64_t& result, const std::string& prompt, const std::string& title, uint64_t currentAddress);

		/*! A mock object that is a placeholder during development of this feature.

			\return MemoryMap object
		*/
		MemoryMap* GetMemoryMap() { return m_memoryMap.get(); }

		/*! Add an analysis segment that specifies how data from the raw file is mapped into a virtual address space

			\param start Starting virtual address
			\param length Length within the virtual address space
			\param dataOffset Data offset in the raw file
			\param dataLength Length of the data to map from the raw file
			\param flags Segment r/w/x flags
		*/
		void AddAutoSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);

		/*! Removes an automatically generated segment from the current segment mapping

			\warning This action is not persistent across saving of a BNDB and must be re-applied each time a BNDB is loaded.

			\param start Virtual address of the start of the segment
			\param length Length of the segment
		*/
		void RemoveAutoSegment(uint64_t start, uint64_t length);

		/*! Creates a user-defined segment that specifies how data from the raw file is mapped into a virtual address space

			\param start Starting virtual address
			\param length Length within the virtual address space
			\param dataOffset Data offset in the raw file
			\param dataLength Length of the data to map from the raw file
			\param flags Segment r/w/x flags
		*/
		void AddUserSegment(uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags);

		/*! Removes a user-defined segment from th current segment mapping

			\param start Virtual address of the start of the segment
			\param length Length of the segment
		*/
		void RemoveUserSegment(uint64_t start, uint64_t length);

		/*! Get the list of registered Segments

			\return The list of registered Segments
		*/
		std::vector<Ref<Segment>> GetSegments();

		/*! Gets the Segment a given virtual address is located in

			\param addr A virtual address
			\return The Segment that virtual address is located im
		*/
		Ref<Segment> GetSegmentAt(uint64_t addr);

		/*! Retrieves the virtual addreses that maps to the given file offset, if possible.

			\param[in] offset Raw file offset
			\param[out] addr Reference to a uint64_t the address will be written to
			\return Whether an address was successfully mapped
		*/
		bool GetAddressForDataOffset(uint64_t offset, uint64_t& addr);

		bool GetDataOffsetForAddress(uint64_t addr, uint64_t& offset);

		/*! Creates an analysis-defined section that can help inform analysis by clarifying what types of data exist in
			what ranges

		 	Note that all data specified must already be mapped by an existing segment.

			\param name Name of the section
			\param start Virtual address of the start of the section
			\param length Length of the section
			\param semantics SectionSemantics of the section
			\param type Optional type of the section
			\param align Optional byte alignment
			\param entrySize Entry Size of the section
			\param linkedSection Optional namee of a linked section
			\param infoSection Optional name of an associated informational section
			\param infoData Optional Info Data
		*/
		void AddAutoSection(const std::string& name, uint64_t start, uint64_t length,
		    BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "", uint64_t align = 1,
		    uint64_t entrySize = 0, const std::string& linkedSection = "", const std::string& infoSection = "",
		    uint64_t infoData = 0);

		/*! Remove an automatically defined section by name

			\param name Name of the section
		*/
		void RemoveAutoSection(const std::string& name);

		/*! Creates a user-defined section that can help inform analysis by clarifying what types of data exist in
			what ranges

		 	Note that all data specified must already be mapped by an existing segment.

			\param name Name of the section
			\param start Virtual address of the start of the section
			\param length Length of the section
			\param semantics SectionSemantics of the section
			\param type Optional type of the section
			\param align Optional byte alignment
			\param entrySize Entry Size of the section
			\param linkedSection Optional namee of a linked section
			\param infoSection Optional name of an associated informational section
			\param infoData Optional Info Data
		*/
		void AddUserSection(const std::string& name, uint64_t start, uint64_t length,
		    BNSectionSemantics semantics = DefaultSectionSemantics, const std::string& type = "", uint64_t align = 1,
		    uint64_t entrySize = 0, const std::string& linkedSection = "", const std::string& infoSection = "",
		    uint64_t infoData = 0);

		/*! Remove a user defined section by name

			\param name Name of the section to remove
		*/
		void RemoveUserSection(const std::string& name);

		/*! Get the list of defined sections

			\return The list of defined sections
		*/
		std::vector<Ref<Section>> GetSections();

		/*! Get the list of sections containing \c addr

			\param addr Address to check
			\return List of sections containing \c addr
		*/
		std::vector<Ref<Section>> GetSectionsAt(uint64_t addr);

		/*! Get a Section by name

			\param name Name of the Section
			\return The Section with that name
		*/
		Ref<Section> GetSectionByName(const std::string& name);

		/*! Create unique names for all items in the input list, modifying them if they are not unique

			\code{.cpp}
		    std::vector<std::string> names = bv.GetUniqueSectionNames({"sect1", "sect1", "sect2"});
			// names == {'sect1', 'sect1#1', 'sect2'}
		 	\endcode

			\param names List of names
			\return List of unique names
		*/
		std::vector<std::string> GetUniqueSectionNames(const std::vector<std::string>& names);

		/*! Get the list of allocated ranges
		   \deprecated This API has been deprecated in favor of GetMappedAddressRanges in 4.0.xxxx

			\return The list of allocated ranges
		*/
		std::vector<BNAddressRange> GetAllocatedRanges();

		/*! Get the list of ranges mapped into the address space

			\return The list of mapped ranges
		*/
		std::vector<BNAddressRange> GetMappedAddressRanges();

		/*! Get the list of ranges that are mapped into the address space and are backed by a target object

			\return The list of backed ranges
		*/
		std::vector<BNAddressRange> GetBackedAddressRanges();

		/*! Get the comment placed at an address

			\param addr Address at which to check for a comment
			\return Comment at that address
		*/
		std::string GetCommentForAddress(uint64_t addr) const;

		/*! Get the list of commented addresses

			\return list of addresses with comments defined at them
		*/
		std::vector<uint64_t> GetCommentedAddresses() const;

		/*! Set the comment at an address

			\param addr Address at which to place a comment
			\param comment Comment to place
		*/
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

		void StoreMetadata(const std::string& key, Ref<Metadata> value, bool isAuto = false);
		Ref<Metadata> QueryMetadata(const std::string& key);
		void RemoveMetadata(const std::string& key);
		Ref<Metadata> GetMetadata();
		Ref<Metadata> GetAutoMetadata();
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

		/*! Returns a list of namespaces for the current BinaryView

			\return A list of namespaces for the current BinaryView
		*/
		std::set<NameSpace> GetNameSpaces() const;

		/*! Internal namespace for the current BinaryView

			\return Internal namespace for the current BinaryView
		*/
		static NameSpace GetInternalNameSpace();

		/*! External namespace for the current BinaryView

			\return External namespace for the current BinaryView
		*/
		static NameSpace GetExternalNameSpace();

		/*! Evaluates a string expression to an integer value.

			The parser uses the following rules:

			- Symbols are defined by the lexer as ``[A-Za-z0-9_:<>][A-Za-z0-9_:$\-<>]+`` or anything enclosed in either single or double quotes
			- Symbols are everything in ``bv.GetSymbols()``, unnamed DataVariables (i.e. ``data_00005000``), unnamed functions (i.e. ``sub_00005000``), or section names (i.e. ``.text``)
			- Numbers are defaulted to hexadecimal thus `_printf + 10` is equivalent to `printf + 0x10` If decimal numbers required use the decimal prefix.
			- Since numbers and symbols can be ambiguous its recommended that you prefix your numbers with the following:

					- ``0x`` - Hexadecimal
					- ``0n`` - Decimal
					- ``0`` - Octal

			- In the case of an ambiguous number/symbol (one with no prefix) for instance ``12345`` we will first attempt
			  to look up the string as a symbol, if a symbol is found its address is used, otherwise we attempt to convert
			  it to a hexadecimal number.
			- The following operations are valid: ``+, -, \*, /, %, (), &, \|, ^, ~``
			- In addition to the above operators there are dereference operators similar to BNIL style IL:

					- ``[<expression>]`` - read the `current address size` at ``<expression>``
					- ``[<expression>].b`` - read the byte at ``<expression>``
					- ``[<expression>].w`` - read the word (2 bytes) at ``<expression>``
					- ``[<expression>].d`` - read the dword (4 bytes) at ``<expression>``
					- ``[<expression>].q`` - read the quadword (8 bytes) at ``<expression>``

			- The ``$here`` (or more succinctly: ``$``) keyword can be used in calculations and is defined as the ``here`` parameter, or the currently selected address
			- The ``$start``/``$end`` keyword represents the address of the first/last bytes in the file respectively


			\param[in] view View object for relative selections
			\param[in] expression Expression to parse
			\param[out] offset Parsed expression
			\param[in] here The location for $here
			\param[out] errorString Any errors that occurred during parsing
			\return Whether the parsing was successful
		*/
		static bool ParseExpression(Ref<BinaryView> view, const std::string& expression, uint64_t& offset,
		    uint64_t here, std::string& errorString);

		/*! Check whether this BinaryView has any defined symbols

			\return Whether this BinaryView has any defined symbols
		*/
		bool HasSymbols() const;

		/*! Check whether this BinaryView has any defined DataVariables

			\return Whether this BinaryView has any defined DataVariables
		*/
		bool HasDataVariables() const;

		Ref<Structure> CreateStructureFromOffsetAccess(const QualifiedName& type, bool* newMemberAdded) const;
		Confidence<Ref<Type>> CreateStructureMemberFromAccess(const QualifiedName& name, uint64_t offset) const;

		/*! Create a logger with a session ID tied to this BinaryView.

		 	Whenever this logger is used, if "Log Scope" is set to "Current Tab", it will only be shown for tabs
		 	Displaying this BinaryView

		 	\see Logger
		 	\see LogRegistry

			\param name Name for the logger
			\return The created Logger
		*/
		Ref<Logger> CreateLogger(const std::string& name);

		/*! Add a magic value to the expression parser

			If the magic value already exists, its value gets updated.
			The magic value can be used in the expression by a `$` followed by its name, e.g., `$foobar`.
		 	It is optional to include the `$` when calling this function, i.e., calling with `foobar` and `$foobar`
		 	has the same effect.

			\param name Name for the magic value to add or update
			\param value Value for the magic value
		*/
		void AddExpressionParserMagicValue(const std::string& name, uint64_t value);

		/*! Remove a magic value from the expression parser

			If the magic value gets referenced after removal, an error will occur during the parsing.

			\param name Name for the magic value to remove
			\param value Value for the magic value
		*/
		void RemoveExpressionParserMagicValue(const std::string& name);

		/*! Add a list of magic value to the expression parser

		 	The vector `names` and `values` must have the same size. The ith name in the `names` will correspond to
		 	the ith value in the `values`.

			If a magic value already exists, its value gets updated.
			The magic value can be used in the expression by a `$` followed by its name, e.g., `$foobar`.
		 	It is optional to include the `$` when calling this function, i.e., calling with `foobar` and `$foobar`
		 	has the same effect.

			\param name Names for the magic values to add or update
			\param value Values for the magic value
		*/
		void AddExpressionParserMagicValues(const std::vector<std::string>& names, const std::vector<uint64_t>& values);

		/*! Remove a list of magic value from the expression parser

			If any of the magic values gets referenced after removal, an error will occur during the parsing.

			\param name Names for the magic value to remove
		*/
		void RemoveExpressionParserMagicValues(const std::vector<std::string>& names);

		/*! Get the value of an expression parser magic value

		 	If the queried magic value exists, the function returns true and the magic value is returned in `value`.
		 	If the queried magic value does not exist, the function returns false.

			\param[in] name Name for the magic value to query
			\param[out] value Value for the magic value
		 	\return Whether the magic value exists
		*/
		bool GetExpressionParserMagicValue(const std::string& name, uint64_t* value);

		Ref<ExternalLibrary> AddExternalLibrary(const std::string& name, Ref<ProjectFile> backingFile, bool isAuto = false);
		void RemoveExternalLibrary(const std::string& name);
		Ref<ExternalLibrary> GetExternalLibrary(const std::string& name);
		std::vector<Ref<ExternalLibrary>> GetExternalLibraries();

		Ref<ExternalLocation> AddExternalLocation(Ref<Symbol> sourceSymbol, Ref<ExternalLibrary> library, std::optional<std::string> targetSymbol, std::optional<uint64_t> targetAddress, bool isAuto = false);
		void RemoveExternalLocation(Ref<Symbol> sourceSymbol);
		Ref<ExternalLocation> GetExternalLocation(Ref<Symbol> sourceSymbol);
		std::vector<Ref<ExternalLocation>> GetExternalLocations();
	};


}
