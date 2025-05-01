#pragma once

#include <binaryninjaapi.h>

namespace BinaryNinja {
	// This set of structs is based on the objc4 source,
	// 		however pointers have been replaced with view_ptr_t

	// Used for pointers within BinaryView, primarily to make it far more clear in typedefs
	// 		whether the size of a field can vary between architectures.
	// These should _not_ be used in sizeof or direct Read() calls.
	typedef uint64_t view_ptr_t;

	typedef struct {
		view_ptr_t name;
		view_ptr_t types;
		view_ptr_t imp;
	} method_t;
	typedef struct {
		uint32_t name;
		uint32_t types;
		uint32_t imp;
	} method_entry_t;
	typedef struct {
		view_ptr_t offset;
		view_ptr_t name;
		view_ptr_t type;
		uint32_t alignmentRaw;
		uint32_t size;
	} ivar_t;
	typedef struct {
		view_ptr_t name;
		view_ptr_t attributes;
	} property_t;
	typedef struct {
		uint32_t entsizeAndFlags;
		uint32_t count;
	} method_list_t;
	typedef struct {
		uint32_t entsizeAndFlags;
		uint32_t count;
	} ivar_list_t;
	typedef struct {
		uint32_t entsizeAndFlags;
		uint32_t count;
	} property_list_t;
	typedef struct {
		uint64_t count;
	} protocol_list_t;
	struct relative_list_list_entry_t {
	    uint64_t imageIndex: 16;
	    int64_t listOffset: 48;
	};
	typedef struct {
		view_ptr_t isa;
		view_ptr_t mangledName;
		view_ptr_t protocols;
		view_ptr_t instanceMethods;
		view_ptr_t classMethods;
		view_ptr_t optionalInstanceMethods;
		view_ptr_t optionalClassMethods;
		view_ptr_t instanceProperties;
		uint32_t size;
		uint32_t flags;
	} protocol_t;
	typedef struct {
		uint32_t flags;
		uint32_t instanceStart;
		uint32_t instanceSize;
		uint32_t reserved;
		view_ptr_t ivarLayout;
		view_ptr_t name;
		view_ptr_t baseMethods;
		view_ptr_t baseProtocols;
		view_ptr_t ivars;
		view_ptr_t weakIvarLayout;
		view_ptr_t baseProperties;
	} class_ro_t;
	typedef struct {
		view_ptr_t isa;
		view_ptr_t super;
		view_ptr_t cache;
		view_ptr_t vtable;
		view_ptr_t data;
	} class_t;
	typedef struct {
		view_ptr_t name;
		view_ptr_t cls;
		view_ptr_t instanceMethods;
		view_ptr_t classMethods;
		view_ptr_t protocols;
		view_ptr_t instanceProperties;
	} category_t;
	typedef struct {
		view_ptr_t receiver;
		view_ptr_t current_class;
	} objc_super2;
	typedef struct {
		view_ptr_t imp;
		view_ptr_t sel;
	} message_ref_t;

	struct Method {
		std::string name;
		std::string types;
		view_ptr_t imp;
	};

	struct Ivar {
		uint32_t offset;
		std::string name;
		std::string type;
		uint32_t alignment;
		uint32_t size;
	};

	struct Property {
		std::string name;
		std::string attributes;
	};

	struct ClassBase {
		std::map<uint64_t, Method> methodList;
		std::map<uint64_t, Ivar> ivarList;
	};

	struct Class {
		std::string name;
		ClassBase instanceClass;
		ClassBase metaClass;

		// Loaded by type processing
		QualifiedName associatedName;
	};

	class Protocol {
	public:
		std::string name;
		std::vector<QualifiedName> protocols;
		ClassBase instanceMethods;
		ClassBase classMethods;
		ClassBase optionalInstanceMethods;
		ClassBase optionalClassMethods;
	};

	struct QualifiedNameOrType {
		BinaryNinja::Ref<BinaryNinja::Type> type = nullptr;
		BinaryNinja::QualifiedName name;
		size_t ptrCount = 0;
	};

	class ObjCReader {
	public:
		virtual ~ObjCReader() = default;

		/*! Read from the current cursor position into buffer `dest` and advance the cursor that many bytes

		    \throws Exception
			\param dest Address to write the read bytes to
			\param len Number of bytes to write
		*/
		virtual void Read(void* dest, size_t len) = 0;

		/*! Read a null-terminated string from the current cursor position

		    \throws Exception
			\return the string
		*/
		virtual std::string ReadCString(size_t maxLength = -1) = 0;

		/*! Read a uint8_t from the current cursor position and advance the cursor by 1 byte

		    \throws Exception
			\return The read value
		*/
		virtual uint8_t Read8() = 0;

		/*! Read a uint16_t from the current cursor position and advance the cursor by 2 bytes

		    \throws Exception
			\return The read value
		*/
		virtual uint16_t Read16() = 0;

		/*! Read a uint32_t from the current cursor position and advance the cursor by 4 bytes

		    \throws Exception
			\return The read value
		*/
		virtual uint32_t Read32() = 0;

		/*! Read a uint64_t from the current cursor position and advance the cursor by 8 bytes

		    \throws Exception
			\return The read value
		*/
		virtual uint64_t Read64() = 0;

		/*! Read a int8_t from the current cursor position and advance the cursor by 1 byte

		    \throws Exception
			\return The read value
		*/
		virtual int8_t ReadS8() = 0;

		/*! Read a int16_t from the current cursor position and advance the cursor by 2 bytes

		    \throws Exception
			\return The read value
		*/
		virtual int16_t ReadS16() = 0;

		/*! Read a int32_t from the current cursor position and advance the cursor by 4 bytes

		    \throws Exception
			\return The read value
		*/
		virtual int32_t ReadS32() = 0;

		/*! Read a int64_t from the current cursor position and advance the cursor by 8 bytes

		    \throws Exception
			\return The read value
		*/
		virtual int64_t ReadS64() = 0;

		/*! Read a pointer from the current cursor position and advance it that many bytes

		    \throws Exception
		    \return The value that was read
		*/
		virtual uint64_t ReadPointer() = 0;

		/*! Get the current cursor position

			\return The current cursor position
		*/
		virtual uint64_t GetOffset() const = 0;

		/*! Set the cursor position

			\param offset The new cursor position
		*/
		virtual void Seek(uint64_t offset) = 0;

		/*! Set the cursor position, relative to the current position

			\param offset Offset to the current cursor position
		*/
		virtual void SeekRelative(int64_t offset) = 0;
	};

	class ObjCProcessor {
		struct Types {
			QualifiedName relativePtr;
			QualifiedName id;
			QualifiedName sel;
			QualifiedName BOOL;
			QualifiedName nsInteger;
			QualifiedName nsuInteger;
			QualifiedName cgFloat;
			QualifiedName cfStringFlag;
			QualifiedName cfString;
			QualifiedName cfStringUTF16;
			QualifiedName imageInfoFlags;
			QualifiedName imageInfoSwiftVersion;
			QualifiedName imageInfo;
			QualifiedName methodEntry;
			QualifiedName method;
			QualifiedName methodList;
			QualifiedName classRO;
			QualifiedName cls;
			QualifiedName category;
			QualifiedName protocol;
			QualifiedName protocolList;
			QualifiedName ivar;
			QualifiedName ivarList;
		} m_typeNames;

		bool m_isBackedByDatabase;
		// TODO(WeiN76LQh): this is to avoid a bug with defining a classes protocol list in the DSC plugin. Remove once fixed
		bool m_skipClassBaseProtocols;

		SymbolQueue* m_symbolQueue = nullptr;
		std::map<uint64_t, Class> m_classes;
		std::map<uint64_t, Class> m_categories;
		std::map<uint64_t, Protocol> m_protocols;
		std::unordered_map<uint64_t, std::string> m_selectorCache;
		std::unordered_map<uint64_t, Method> m_localMethods;

		// Required for workflow_objc type heuristics, should be removed when that is no longer a thing.
		std::map<uint64_t, std::string> m_selRefToName;
		std::map<uint64_t, std::vector<uint64_t>> m_selRefToImplementations;
		std::map<uint64_t, std::vector<uint64_t>> m_selToImplementations;
		// --

		uint64_t ReadPointerAccountingForRelocations(ObjCReader* reader);
		std::unordered_map<uint64_t, uint64_t> m_relocationPointerRewrites;

		static Ref<Metadata> SerializeMethod(uint64_t loc, const Method& method);
		static Ref<Metadata> SerializeClass(uint64_t loc, const Class& cls);
		Ref<Metadata> SerializeMetadata();

		std::vector<QualifiedNameOrType> ParseEncodedType(const std::string& type);
		void DefineObjCSymbol(BNSymbolType symbolType, QualifiedName typeName, const std::string& name, uint64_t addr, bool deferred);
		void DefineObjCSymbol(BNSymbolType symbolType, Ref<Type> type, const std::string& name, uint64_t addr, bool deferred);
		void ReadIvarList(ObjCReader* reader, ClassBase& cls, std::string_view name, view_ptr_t start);
		void ReadMethodList(ObjCReader* reader, ClassBase& cls, std::string_view name, view_ptr_t start);
		void ReadListOfMethodLists(ObjCReader* reader, ClassBase& cls, std::string_view name, view_ptr_t start);
		void LoadClasses(ObjCReader* reader, Ref<Section> listSection);
		void LoadCategories(ObjCReader* reader, Ref<Section> listSection);
		void LoadProtocols(ObjCReader* reader, Ref<Section> listSection);
		void GenerateClassTypes();
		bool ApplyMethodType(Class& cls, Method& method, bool isInstanceMethod);
		void ApplyMethodTypes(Class& cls);

		void PostProcessObjCSections(ObjCReader* reader);

	protected:
		Ref<BinaryView> m_data;
		Ref<Logger> m_logger;

		virtual uint64_t GetObjCRelativeMethodBaseAddress(ObjCReader* reader);
		virtual void GetRelativeMethod(ObjCReader* reader, method_t& meth);
		virtual std::shared_ptr<ObjCReader> GetReader() = 0;
		// Because an objective-c processor might have access to other non-view symbols that we want to retrieve.
		// By default, this will just get symbol at the address in the view.
		virtual Ref<Symbol> GetSymbol(uint64_t address);
		virtual Ref<Section> GetSectionWithName(const char* sectionName);

	public:
		virtual ~ObjCProcessor() = default;

		ObjCProcessor(BinaryView* data, const char* loggerName, bool isBackedByDatabase, bool skipClassBaseProtocols = false);
		// TODO: Instead of passing in image name the processor must be given section refs in a structure that outlines all objc sections.
		void ProcessObjCData();
		void ProcessCFStrings();
		void AddRelocatedPointer(uint64_t location, uint64_t rewrite);
	};
}

