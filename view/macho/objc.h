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
	typedef struct {
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

	struct QualifiedNameOrType {
		BinaryNinja::Ref<BinaryNinja::Type> type = nullptr;
		BinaryNinja::QualifiedName name;
		size_t ptrCount = 0;
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
			QualifiedName ivar;
			QualifiedName ivarList;
		} m_typeNames;

		bool m_isBackedByDatabase;

		BinaryView* m_data;
		SymbolQueue* m_symbolQueue = nullptr;
		Ref<Logger> m_logger;
		std::map<uint64_t, Class> m_classes;
		std::map<uint64_t, Class> m_categories;
		std::unordered_map<uint64_t, std::string> m_selectorCache;
		std::unordered_map<uint64_t, Method> m_localMethods;

		// Required for workflow_objc type heuristics, should be removed when that is no longer a thing.
		std::map<uint64_t, std::string> m_selRefToName;
		std::map<uint64_t, std::vector<uint64_t>> m_selRefToImplementations;
		std::map<uint64_t, std::vector<uint64_t>> m_selToImplementations;
		// --

		uint64_t ReadPointerAccountingForRelocations(BinaryReader* reader);
		std::unordered_map<uint64_t, uint64_t> m_relocationPointerRewrites;

		static Ref<Metadata> SerializeMethod(uint64_t loc, const Method& method);
		static Ref<Metadata> SerializeClass(uint64_t loc, const Class& cls);

		Ref<Metadata> SerializeMetadata();
		std::vector<QualifiedNameOrType> ParseEncodedType(const std::string& type);
		void DefineObjCSymbol(BNSymbolType symbolType, QualifiedName typeName, const std::string& name, uint64_t addr, bool deferred);
		void DefineObjCSymbol(BNSymbolType symbolType, Ref<Type> type, const std::string& name, uint64_t addr, bool deferred);
		void ReadIvarList(BinaryReader* reader, ClassBase& cls, std::string name, view_ptr_t start);
		void ReadMethodList(BinaryReader* reader, ClassBase& cls, std::string name, view_ptr_t start);
		void LoadClasses(BinaryReader* reader, Ref<Section> listSection);
		void LoadCategories(BinaryReader* reader, Ref<Section> listSection);
		void GenerateClassTypes();
		bool ApplyMethodType(Class& cls, Method& method, bool isInstanceMethod);
		void ApplyMethodTypes(Class& cls);
		void PostProcessObjCSections(BinaryReader* reader);
	public:
		static bool ViewHasObjCMetadata(BinaryView* data);
		ObjCProcessor(BinaryView* data, bool isBackedByDatabase);
		void ProcessObjCData();
		void AddRelocatedPointer(uint64_t location, uint64_t rewrite);
	};
}

