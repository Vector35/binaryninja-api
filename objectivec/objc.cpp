#include "objc.h"
#include "inttypes.h"
#include <optional>
#include <string>
#include <type_traits>

#define RELEASE_ASSERT(condition) ((condition) ? (void)0 : (std::abort(), (void)0))

#define MAX_PROTOCOL_COUNT 0x1000
#define MAX_METHOD_LIST_COUNT 0x1000
#define MAX_IVAR_LIST_COUNT 0x1000

using namespace BinaryNinja;

namespace {

	// ScopedSingleton is a thread-local singleton that allows for scoped
	// instantiation and destruction of an object. It is useful for managing
	// resources that should only exist during a specific scope, but where it
	// would be inconvenient to pass the object around explicitly.
	//
	// Calling `Make` initializes the thread-local singleton and returns a `Guard`
	// object. When the `Guard` object goes out of scope, the singleton is destroyed.
	template <typename T>
	class ScopedSingleton
	{
		static thread_local T* current;

	public:
		class Guard
		{
			friend class ScopedSingleton;
			Guard() = default;

		public:
			~Guard()
			{
				delete current;
				current = nullptr;
			}
			Guard(Guard&&) = default;
			Guard(const Guard&) = delete;
			Guard& operator=(const Guard&) = delete;
		};

		static T& Get()
		{
			RELEASE_ASSERT(current);
			return *current;
		}

		static Guard Make()
		{
			RELEASE_ASSERT(!current);
			current = new T();
			return Guard {};
		}
	};

	template <typename T>
	thread_local T* ScopedSingleton<T>::current = nullptr;

	using ScopedSymbolQueue = ScopedSingleton<SymbolQueue>;

	// Attempt to recover an Objective-C class name from the symbol's name.
	// Note: classes defined in the current image should be looked up in m_classes
	// rather than using this function.
	std::optional<std::string> ClassNameFromSymbolName(const Ref<Symbol>& symbol)
	{
		std::string_view symbolName = symbol->GetFullNameRef();

		// Symbols named `_OBJC_CLASS_$_` are references to external classes.
		if (symbolName.size() > 14 && symbolName.rfind("_OBJC_CLASS_$_", 0) == 0)
			return std::string(symbolName.substr(14));

		// Symbols named `cls_` are classes defined in a loaded image other than
		// the image currently being analyzed.
		if (symbolName.size() > 4 && symbolName.rfind("cls_", 0) == 0)
			return std::string(symbolName.substr(4));

		return std::nullopt;
	}

	// Given a selector component such as `initWithPath' and a prefix of `initWith`, returns `path`.
	std::optional<std::string> SelectorComponentWithoutPrefix(std::string_view prefix, std::string_view component)
	{
		if (component.size() <= prefix.size() || component.rfind(prefix.data(), 0) != 0
			|| !isupper(component[prefix.size()]))
		{
			return std::nullopt;
		}

		std::string result(component.substr(prefix.size()));

		// Lowercase the first character if the second character is not also uppercase.
		// This ensures we leave initialisms such as `URL` alone.
		if (result.size() > 1 && islower(result[1]))
			result[0] = tolower(result[0]);

		return result;
	}

	std::string ArgumentNameFromSelectorComponent(std::string component)
	{
		// TODO: Handle other common patterns such as <do some action>With<arg>: and <do some action>For<arg>:
		for (const auto& prefix : {"initWith", "with", "and", "using", "set", "read", "to", "for"})
		{
			if (auto argumentName = SelectorComponentWithoutPrefix(prefix, component); argumentName.has_value())
				return std::move(*argumentName);
		}

		return component;
	}

	Ref<Type> NamedType(const std::string& name)
	{
		NamedTypeReferenceBuilder builder;
		builder.SetName(QualifiedName(name));
		return Type::NamedType(builder.Finalize());
	}

}  // namespace

Ref<Metadata> ObjCProcessor::SerializeMethod(uint64_t loc, const Method& method)
{
	std::map<std::string, Ref<Metadata>> methodMeta;

	methodMeta["loc"] = new Metadata(loc);
	methodMeta["name"] = new Metadata(method.name);
	methodMeta["types"] = new Metadata(method.types);
	methodMeta["imp"] = new Metadata(method.imp);

	return new Metadata(methodMeta);
}


Ref<Metadata> ObjCProcessor::SerializeClass(uint64_t loc, const Class& cls)
{
	std::map<std::string, Ref<Metadata>> clsMeta;

	clsMeta["loc"] = new Metadata(loc);
	clsMeta["name"] = new Metadata(cls.name);
	clsMeta["typeName"] = new Metadata(cls.associatedName.GetString());

	std::vector<uint64_t> instanceMethods;
	std::vector<uint64_t> classMethods;
	instanceMethods.reserve(cls.instanceClass.methodList.size());
	classMethods.reserve(cls.metaClass.methodList.size());
	for (const auto& [location, _] : cls.instanceClass.methodList)
		instanceMethods.push_back(location);

	clsMeta["instanceMethods"] = new Metadata(instanceMethods);
	clsMeta["classMethods"] = new Metadata(classMethods);

	return new Metadata(clsMeta);
}

Ref<Metadata> ObjCProcessor::SerializeMetadata()
{
	std::map<std::string, Ref<Metadata>> viewMeta;
	viewMeta["version"] = new Metadata((uint64_t)1);

	std::vector<Ref<Metadata>> classes;
	classes.reserve(m_classes.size());
	std::vector<Ref<Metadata>> categories;
	categories.reserve(m_categories.size());
	std::vector<Ref<Metadata>> methods;
	methods.reserve(m_localMethods.size());

	for (const auto& [clsLoc, cls] : m_classes)
		classes.push_back(SerializeClass(clsLoc, cls));
	viewMeta["classes"] = new Metadata(classes);
	for (const auto& [catLoc, cat] : m_categories)
		categories.push_back(SerializeClass(catLoc, cat));
	viewMeta["categories"] = new Metadata(categories);
	for (const auto& [methodLoc, method] : m_localMethods)
		methods.push_back(SerializeMethod(methodLoc, method));
	viewMeta["methods"] = new Metadata(methods);

	// Required for workflow_objc type guessing, should be removed when that is no longer a thing.
	std::vector<Ref<Metadata>> selRefToImps;
	selRefToImps.reserve(m_selRefToImplementations.size());
	for (const auto& [selRef, imps] : m_selRefToImplementations)
	{
		std::vector<Ref<Metadata>> mapBase = {new Metadata(selRef), new Metadata(imps)};
		Ref<Metadata> mapObject = new Metadata(mapBase);
		selRefToImps.push_back(mapObject);
	}
	viewMeta["selRefImplementations"] = new Metadata(selRefToImps);

	std::vector<Ref<Metadata>> selToImps;
	selToImps.reserve(m_selToImplementations.size());
	for (const auto& [selRef, imps] : m_selToImplementations)
	{
		std::vector<Ref<Metadata>> mapBase = {new Metadata(selRef), new Metadata(imps)};
		Ref<Metadata> mapObject = new Metadata(mapBase);
		selToImps.push_back(mapObject);
	}
	viewMeta["selImplementations"] = new Metadata(selToImps);

	std::vector<Ref<Metadata>> selRefToName;
	selRefToName.reserve(m_selRefToName.size());
	for (const auto& [selRef, name] : m_selRefToName)
	{
		std::vector<Ref<Metadata>> mapBase = {new Metadata(selRef), new Metadata(name)};
		Ref<Metadata> mapObject = new Metadata(mapBase);
		selRefToName.push_back(mapObject);
	}
	viewMeta["selRefToName"] = new Metadata(selRefToName);
	// ---


	return new Metadata(viewMeta);
}

std::vector<QualifiedNameOrType> ObjCProcessor::ParseEncodedType(const std::string& encodedType)
{
	std::vector<QualifiedNameOrType> result;
	int pointerDepth = 0;

	bool readingNamedType = false;
	std::string namedType;
	int readingStructDepth = 0;
	std::string structType;
	char last = 0;

	for (char c : encodedType)
	{
		if (readingNamedType && c != '"')
		{
			namedType.push_back(c);
			last = c;
			continue;
		}
		else if (readingStructDepth > 0 && c != '{' && c != '}')
		{
			structType.push_back(c);
			last = c;
			continue;
		}

		if (std::isdigit(c))
			continue;

		QualifiedNameOrType nameOrType;
		std::string qualifiedName;

		switch (c)
		{
		case '^':
			pointerDepth++;
			last = c;
			continue;

		case '"':
			if (!readingNamedType)
			{
				readingNamedType = true;
				if (last == '@')
					result.pop_back();  // We added an 'id' in the last cycle, remove it
				last = c;
				continue;
			}
			else
			{
				readingNamedType = false;
				nameOrType.name = QualifiedName(namedType);
				nameOrType.ptrCount = 1;
				break;
			}
		case '{':
			readingStructDepth++;
			last = c;
			continue;
		case '}':
			readingStructDepth--;
			if (readingStructDepth < 0)
				return {};  // seriously malformed type.

			if (readingStructDepth == 0)
			{
				// TODO: Emit real struct types
				nameOrType.type = Type::PointerType(m_data->GetAddressSize(), Type::VoidType());
				break;
			}
			last = c;
			continue;
		case 'v':
			nameOrType.type = Type::VoidType();
			break;
		case 'c':
			nameOrType.type = Type::IntegerType(1, true);
			break;
		case 'A':
		case 'C':
			nameOrType.type = Type::IntegerType(1, false);
			break;
		case 's':
			nameOrType.type = Type::IntegerType(2, true);
			break;
		case 'S':
			nameOrType.type = Type::IntegerType(2, false);
			break;
		case 'i':
			nameOrType.type = Type::IntegerType(4, true);
			break;
		case 'I':
			nameOrType.type = Type::IntegerType(4, false);
			break;
		case 'l':
			nameOrType.type = Type::IntegerType(4, true);
			break;
		case 'L':
			nameOrType.type = Type::IntegerType(4, false);
			break;
		case 'q':
			nameOrType.type = Type::IntegerType(8, true);
			break;
		case 'Q':
			nameOrType.type = Type::IntegerType(8, false);
			break;
		case 'f':
			nameOrType.type = Type::FloatType(4);
			break;
		case 'd':
			nameOrType.type = Type::FloatType(8);
			break;
		case 'b':
		case 'B':
			nameOrType.type = Type::BoolType();
			break;
		case '*':
			nameOrType.type = Type::PointerType(m_data->GetAddressSize(), Type::IntegerType(1, true));
			break;
		case '@':
			nameOrType.type = m_types.id;
			// There can be a type after this, like @"NSString", that overrides this
			// The handler for " will catch it and drop this "id" entry.
			break;
		case ':':
			nameOrType.type = m_types.sel;
			break;
		case '#':
			qualifiedName = "objc_class_t";
			break;
		case '?':
			if (last == '@')
			{
				// A pointer to a Clang block is encoded as `@?`. For now we continue to represent this
				// as `id` as we cannot represent block types.
				last = c;
				continue;
			}
			[[fallthrough]];
		case 'T':
			nameOrType.type = Type::PointerType(8, Type::VoidType());
			break;
		default:
			// BNLogWarn("Unknown type specifier %c", c);
			last = c;
			continue;
		}

		while (pointerDepth)
		{
			if (nameOrType.type)
				nameOrType.type = Type::PointerType(8, nameOrType.type);
			else
				nameOrType.ptrCount++;

			pointerDepth--;
		}

		if (!qualifiedName.empty())
			nameOrType.name = QualifiedName(qualifiedName);

		if (nameOrType.type == nullptr && nameOrType.name.IsEmpty())
		{
			nameOrType.type = Type::VoidType();
		}

		result.push_back(nameOrType);
		last = c;
	}

	return result;
}

void ObjCProcessor::DefineObjCSymbol(
	BNSymbolType type, QualifiedName typeName, const std::string& name, uint64_t addr, bool deferred)
{
	DefineObjCSymbol(type, m_data->GetTypeByName(typeName), name, addr, deferred);
}

void ObjCProcessor::DefineObjCSymbol(
	BNSymbolType type, Ref<Type> typeRef, const std::string& name, uint64_t addr, bool deferred)
{
	if (name.size() == 0 || addr == 0)
		return;

	auto process = [=, this]() {
		NameSpace nameSpace = m_data->GetInternalNameSpace();
		if (type == ExternalSymbol)
		{
			nameSpace = m_data->GetExternalNameSpace();
		}

		std::string shortName = name;
		std::string fullName = name;

		QualifiedName varName;

		return std::pair<Ref<Symbol>, Ref<Type>>(
			new Symbol(type, shortName, fullName, name, addr, LocalBinding, nameSpace), typeRef);
	};

	auto defineSymbol = [this](Ref<Symbol> symbol, const Confidence<Ref<Type>>& type) {
		uint64_t symbolAddress = symbol->GetAddress();
		if (Ref<Symbol> existingSymbol = m_data->GetSymbolByAddress(symbolAddress))
		{
			if (existingSymbol->IsAutoDefined() && existingSymbol->GetType() == symbol->GetType() && existingSymbol->GetRawNameRef() == symbol->GetRawNameRef())
				return;

			m_data->UndefineAutoSymbol(existingSymbol);
		}

		// Armv7/Thumb: This will rewrite the symbol's address.
		// e.g. We pass in 0xc001, it will rewrite it to 0xc000 and create the function w/ the "thumb2" arch.
		Ref<Platform> targetPlatform = m_data->GetDefaultPlatform()->GetAssociatedPlatformByAddress(symbolAddress);
		if (symbol->GetType() == FunctionSymbol)
		{
			// For thumb2 we want to get the adjusted address, we can do that using the target function.
			Ref<Function> targetFunction = m_data->GetAnalysisFunction(targetPlatform, symbolAddress);
			if (targetFunction && type.GetValue())
				targetFunction->ApplyAutoDiscoveredType(type.GetValue());

			auto adjustedSym = new Symbol(FunctionSymbol, symbol->GetShortName(), symbol->GetFullName(), symbol->GetRawName(), symbolAddress);
			m_data->DefineAutoSymbol(adjustedSym);
		}
		else
		{
			// Other symbol types can just use this, they don't need to worry about linear sweep removing them.
			m_data->DefineAutoSymbolAndVariableOrFunction(targetPlatform, symbol, type);
		}
	};

	if (!deferred)
	{
		ScopedSymbolQueue::Get().Append(process, defineSymbol);
	}
	else
	{
		auto [symbol, type]  = process();
		defineSymbol(symbol, type);
	}
}

void ObjCProcessor::LoadClasses(ObjCReader* reader, Ref<Section> classPtrSection)
{
	if (!classPtrSection)
		return;
	auto size = classPtrSection->GetEnd() - classPtrSection->GetStart();
	if (size == 0)
		return;
	auto ptrSize = m_data->GetAddressSize();
	auto ptrCount = size / ptrSize;

	auto classPtrSectionStart = classPtrSection->GetStart();
	for (size_t i = 0; i < ptrCount; i++)
	{
		Class cls;

		view_ptr_t classPtr;
		class_t clsStruct;
		class_ro_t classRO;

		bool hasValidMetaClass = false;
		bool hasValidMetaClassRO = false;
		class_t metaClsStruct;
		class_ro_t metaClassRO;

		view_ptr_t classPointerLocation = classPtrSectionStart + (i * m_data->GetAddressSize());
		reader->Seek(classPointerLocation);

		classPtr = ReadPointerAccountingForRelocations(reader);
		reader->Seek(classPtr);
		try
		{
			clsStruct.isa = ReadPointerAccountingForRelocations(reader);
			clsStruct.super = reader->ReadPointer();
			clsStruct.cache = reader->ReadPointer();
			clsStruct.vtable = reader->ReadPointer();
			clsStruct.data = ReadPointerAccountingForRelocations(reader);
		}
		catch (...)
		{
			m_logger->LogError("Failed to read class data at 0x%llx pointed to by @ 0x%llx", reader->GetOffset(),
				classPointerLocation);
			continue;
		}
		if (clsStruct.data & 1)
		{
			m_logger->LogInfo("Skipping class at 0x%llx as it contains swift types", classPtr);
			continue;
		}
		// unset first two bits
		view_ptr_t classROPtr = clsStruct.data & ~3;
		reader->Seek(classROPtr);
		try
		{
			classRO.flags = reader->Read32();
			classRO.instanceStart = reader->Read32();
			classRO.instanceSize = reader->Read32();
			if (m_data->GetAddressSize() == 8)
				classRO.reserved = reader->Read32();
			classRO.ivarLayout = ReadPointerAccountingForRelocations(reader);
			classRO.name = ReadPointerAccountingForRelocations(reader);
			classRO.baseMethods = ReadPointerAccountingForRelocations(reader);
			classRO.baseProtocols = ReadPointerAccountingForRelocations(reader);
			classRO.ivars = ReadPointerAccountingForRelocations(reader);
			classRO.weakIvarLayout = ReadPointerAccountingForRelocations(reader);
			classRO.baseProperties = ReadPointerAccountingForRelocations(reader);
		}
		catch (...)
		{
			m_logger->LogError("Failed to read class RO data at 0x%llx. 0x%llx, objc_class_t @ 0x%llx",
				reader->GetOffset(), classPointerLocation, classROPtr);
			continue;
		}

		auto namePtr = classRO.name;

		std::string name;

		reader->Seek(namePtr);
		try
		{
			name = reader->ReadCString();
		}
		catch (...)
		{
			m_logger->LogWarn(
				"Failed to read class name at 0x%llx. Class has been given the placeholder name \"0x%llx\" ", namePtr,
				classPtr);
			char hexString[9];
			hexString[8] = 0;
			snprintf(hexString, sizeof(hexString), "%" PRIx64, classPtr);
			name = "0x" + std::string(hexString);
		}

		cls.name = name;

		DefineObjCSymbol(BNSymbolType::DataSymbol,
			Type::PointerType(m_data->GetAddressSize(), m_data->GetTypeByName(m_typeNames.cls)), "clsPtr_" + name,
			classPointerLocation, true);
		DefineObjCSymbol(BNSymbolType::DataSymbol, m_typeNames.cls, "cls_" + name, classPtr, true);
		DefineObjCSymbol(BNSymbolType::DataSymbol, m_typeNames.classRO, "cls_ro_" + name, classROPtr, true);
		DefineObjCSymbol(BNSymbolType::DataSymbol, Type::ArrayType(Type::IntegerType(1, true), name.size() + 1),
			"clsName_" + name, classRO.name, true);
		if (classRO.baseProtocols && !m_skipClassBaseProtocols)
		{
			DefineObjCSymbol(BNSymbolType::DataSymbol, Type::NamedType(m_data, m_typeNames.protocolList),
				"clsProtocols_" + name, classRO.baseProtocols, true);
			reader->Seek(classRO.baseProtocols);
			uint32_t count = reader->Read64();
			view_ptr_t addr = reader->GetOffset();
			for (uint32_t j = 0; j < count; j++)
			{
				m_data->DefineDataVariable(
					addr, Type::PointerType(ptrSize, Type::NamedType(m_data, m_typeNames.protocol)));
				addr += ptrSize;
			}
		}

		if (clsStruct.isa)
		{
			reader->Seek(clsStruct.isa);
			try
			{
				metaClsStruct.isa = ReadPointerAccountingForRelocations(reader);
				metaClsStruct.super = reader->ReadPointer();
				metaClsStruct.cache = reader->ReadPointer();
				metaClsStruct.vtable = reader->ReadPointer();
				metaClsStruct.data = ReadPointerAccountingForRelocations(reader) & ~1;
				DefineObjCSymbol(BNSymbolType::DataSymbol, m_typeNames.cls, "metacls_" + name, clsStruct.isa, true);
				hasValidMetaClass = true;
			}
			catch (...)
			{
				m_logger->LogWarn("Failed to read metaclass data at 0x%llx pointed to by objc_class_t @ 0x%llx",
					reader->GetOffset(), classPtr);
			}
		}
		if (hasValidMetaClass && (metaClsStruct.data & 1))
		{
			m_logger->LogInfo("Skipping metaclass at 0x%llx as it contains swift types", classPtr);
			hasValidMetaClass = false;
		}
		if (hasValidMetaClass)
		{
			reader->Seek(metaClsStruct.data);
			try
			{
				metaClassRO.flags = reader->Read32();
				metaClassRO.instanceStart = reader->Read32();
				metaClassRO.instanceSize = reader->Read32();
				if (m_data->GetAddressSize() == 8)
					metaClassRO.reserved = reader->Read32();
				metaClassRO.ivarLayout = ReadPointerAccountingForRelocations(reader);
				metaClassRO.name = ReadPointerAccountingForRelocations(reader);
				metaClassRO.baseMethods = ReadPointerAccountingForRelocations(reader);
				metaClassRO.baseProtocols = ReadPointerAccountingForRelocations(reader);
				metaClassRO.ivars = ReadPointerAccountingForRelocations(reader);
				metaClassRO.weakIvarLayout = ReadPointerAccountingForRelocations(reader);
				metaClassRO.baseProperties = ReadPointerAccountingForRelocations(reader);
				DefineObjCSymbol(
					BNSymbolType::DataSymbol, m_typeNames.classRO, "metacls_ro_" + name, metaClsStruct.data, true);
				hasValidMetaClassRO = true;
			}
			catch (...)
			{
				m_logger->LogWarn("Failed to read metaclass RO data at 0x%llx pointed to by meta objc_class_t @ 0x%llx",
					reader->GetOffset(), clsStruct.isa);
			}
		}

		if (classRO.baseMethods)
		{
			try
			{
				ReadMethodList(reader, cls.instanceClass, name, classRO.baseMethods);
			}
			catch (...)
			{
				m_logger->LogError("Failed to read the method list for class pointed to by 0x%llx", clsStruct.data);
			}
		}
		if (hasValidMetaClassRO && metaClassRO.baseMethods)
		{
			try
			{
				ReadMethodList(reader, cls.metaClass, name, metaClassRO.baseMethods);
			}
			catch (...)
			{
				m_logger->LogError("Failed to read the method list for metaclass pointed to by 0x%llx", clsStruct.data);
			}
		}

		if (classRO.ivars)
		{
			try
			{
				ReadIvarList(reader, cls.instanceClass, name, classRO.ivars);
			}
			catch (...)
			{
				m_logger->LogError("Failed to process ivars for class at 0x%llx", clsStruct.data);
			}
		}
		m_classes[classPtr] = cls;
	}
}

std::optional<std::string> ObjCProcessor::ClassNameForTargetOfPointerAt(ObjCReader* reader, uint64_t offset)
{
	auto savedOffset = reader->GetOffset();
	reader->Seek(offset);
	auto target = ReadPointerAccountingForRelocations(reader);
	reader->Seek(savedOffset);

	if (target) {
		// Classes defined in the current image must be looked up in m_classes
		// as adding their symbol may be deferred.
		if (auto it = m_classes.find(target); it != m_classes.end())
			return it->second.name;

		// Classes defined in other images are looked up by their symbol name.
		// This is common for cross-image references in the shared cache.
		if (auto symbol = GetSymbol(target))
		{
			if (auto className = ClassNameFromSymbolName(symbol))
				return *className;
		}
	}

	// If there's no target, or we can't find a symbol for it, check whether the pointer has a relocation
	// that contains a symbol. This is the case for cross-image references outside of the shared cache.
	for (const auto& relocation : m_data->GetRelocationsAt(offset))
	{
		if (auto symbol = relocation->GetSymbol())
			return ClassNameFromSymbolName(symbol);
	}

	return std::nullopt;
}

void ObjCProcessor::LoadCategories(ObjCReader* reader, Ref<Section> classPtrSection)
{
	if (!classPtrSection)
		return;
	auto size = classPtrSection->GetEnd() - classPtrSection->GetStart();
	if (size == 0)
		return;
	auto ptrSize = m_data->GetAddressSize();

	auto classPtrSectionStart = classPtrSection->GetStart();
	auto classPtrSectionEnd = classPtrSection->GetEnd();

	auto catType = Type::NamedType(m_data, m_typeNames.category);
	auto ptrType = Type::PointerType(m_data->GetDefaultArchitecture(), catType);
	for (size_t i = classPtrSectionStart; i < classPtrSectionEnd; i += ptrSize)
	{
		Class category;
		category_t cat;

		reader->Seek(i);
		auto catLocation = ReadPointerAccountingForRelocations(reader);
		reader->Seek(catLocation);

		try
		{
			cat.name = ReadPointerAccountingForRelocations(reader);
			cat.cls = ReadPointerAccountingForRelocations(reader);
			cat.instanceMethods = ReadPointerAccountingForRelocations(reader);
			cat.classMethods = ReadPointerAccountingForRelocations(reader);
			cat.protocols = ReadPointerAccountingForRelocations(reader);
			cat.instanceProperties = ReadPointerAccountingForRelocations(reader);
		}
		catch (...)
		{
			m_logger->LogError("Failed to read category pointed to by 0x%llx", i);
			continue;
		}

		std::string categoryAdditionsName;
		std::string categoryBaseClassName =
			ClassNameForTargetOfPointerAt(reader, catLocation + ptrSize).value_or(std::string());

		if (categoryBaseClassName.empty())
		{
			m_logger->LogInfo("Using base address as stand-in classname for category at 0x%llx", catLocation);
			categoryBaseClassName = fmt::format("{:x}", catLocation);
		}
		try
		{
			reader->Seek(cat.name);
			categoryAdditionsName = reader->ReadCString();
		}
		catch (...)
		{
			m_logger->LogWarn(
				"Failed to read category name for category at 0x%llx. Using base address as stand-in category name",
				catLocation);
			categoryAdditionsName = fmt::format("{:x}", catLocation);
		}
		category.name = categoryBaseClassName + " (" + categoryAdditionsName + ")";
		DefineObjCSymbol(BNSymbolType::DataSymbol, ptrType, "categoryPtr_" + category.name, i, true);
		DefineObjCSymbol(BNSymbolType::DataSymbol, catType, "category_" + category.name, catLocation, true);

		if (cat.instanceMethods)
		{
			try
			{
				ReadMethodList(reader, category.instanceClass, category.name, cat.instanceMethods);
			}
			catch (...)
			{
				m_logger->LogError(
					"Failed to read the instance method list for category pointed to by 0x%llx", catLocation);
			}
		}
		if (cat.classMethods)
		{
			try
			{
				ReadMethodList(reader, category.metaClass, category.name, cat.classMethods);
			}
			catch (...)
			{
				m_logger->LogError(
					"Failed to read the class method list for category pointed to by 0x%llx", catLocation);
			}
		}
		m_categories[catLocation] = category;
	}
}

void ObjCProcessor::LoadProtocols(ObjCReader* reader, Ref<Section> listSection)
{
	if (!listSection)
		return;
	auto size = listSection->GetEnd() - listSection->GetStart();
	if (size == 0)
		return;
	auto ptrSize = m_data->GetAddressSize();

	auto listSectionStart = listSection->GetStart();
	auto listSectionEnd = listSection->GetEnd();

	auto protocolType = Type::NamedType(m_data, m_typeNames.protocol);
	auto ptrType = Type::PointerType(m_data->GetDefaultArchitecture(), protocolType);
	for (size_t i = listSectionStart; i < listSectionEnd; i += ptrSize)
	{
		protocol_t protocol;
		reader->Seek(i);
		auto protocolLocation = ReadPointerAccountingForRelocations(reader);
		reader->Seek(protocolLocation);

		try
		{
			protocol.isa = ReadPointerAccountingForRelocations(reader);
			protocol.mangledName = ReadPointerAccountingForRelocations(reader);
			protocol.protocols = ReadPointerAccountingForRelocations(reader);
			protocol.instanceMethods = ReadPointerAccountingForRelocations(reader);
			protocol.classMethods = ReadPointerAccountingForRelocations(reader);
			protocol.optionalInstanceMethods = ReadPointerAccountingForRelocations(reader);
			protocol.optionalClassMethods = ReadPointerAccountingForRelocations(reader);
			protocol.instanceProperties = ReadPointerAccountingForRelocations(reader);
		}
		catch (...)
		{
			m_logger->LogError("Failed to read protocol pointed to by 0x%llx", i);
			continue;
		}

		std::string protocolName;
		try
		{
			reader->Seek(protocol.mangledName);
			protocolName = reader->ReadCString();
			DefineObjCSymbol(BNSymbolType::DataSymbol,
				Type::ArrayType(Type::IntegerType(1, true), protocolName.size() + 1), "protocolName_" + protocolName,
				protocol.mangledName, true);
		}
		catch (...)
		{
			m_logger->LogError(
				"Failed to read protocol name for protocol at 0x%llx. Using base address as stand-in protocol name",
				protocolLocation);
			protocolName = fmt::format("{:x}", protocolLocation);
		}

		Protocol protocolClass;
		protocolClass.name = protocolName;
		DefineObjCSymbol(BNSymbolType::DataSymbol, ptrType, "protocolPtr_" + protocolName, i, true);
		DefineObjCSymbol(BNSymbolType::DataSymbol, protocolType, "protocol_" + protocolName, protocolLocation, true);
		if (protocol.protocols)
		{
			DefineObjCSymbol(BNSymbolType::DataSymbol, Type::NamedType(m_data, m_typeNames.protocolList),
				"protoProtocols_" + protocolName, protocol.protocols, true);
			reader->Seek(protocol.protocols);
			uint32_t count = reader->Read64();
			if (count > MAX_PROTOCOL_COUNT)
			{
				m_logger->LogWarn("List of protocols at 0x%llx has too large a count of 0x%x, skipping...", protocol.protocols, count);
				continue;
			}
			view_ptr_t addr = reader->GetOffset();
			for (uint32_t j = 0; j < count; j++)
			{
				m_data->DefineDataVariable(
					addr, Type::PointerType(ptrSize, Type::NamedType(m_data, m_typeNames.protocol)));
				addr += ptrSize;
			}
		}

		if (protocol.instanceMethods)
		{
			try
			{
				ReadMethodList(reader, protocolClass.instanceMethods, protocolName, protocol.instanceMethods);
			}
			catch (...)
			{
				m_logger->LogError(
					"Failed to read the instance method list for protocol pointed to by 0x%llx", protocolLocation);
			}
		}
		if (protocol.classMethods)
		{
			try
			{
				ReadMethodList(reader, protocolClass.classMethods, protocolName, protocol.classMethods);
			}
			catch (...)
			{
				m_logger->LogError(
					"Failed to read the class method list for protocol pointed to by 0x%llx", protocolLocation);
			}
		}
		if (protocol.optionalInstanceMethods)
		{
			try
			{
				ReadMethodList(
					reader, protocolClass.optionalInstanceMethods, protocolName, protocol.optionalInstanceMethods);
			}
			catch (...)
			{
				m_logger->LogError("Failed to read the optional instance method list for protocol pointed to by 0x%llx",
					protocolLocation);
			}
		}
		if (protocol.optionalClassMethods)
		{
			try
			{
				ReadMethodList(reader, protocolClass.optionalClassMethods, protocolName, protocol.optionalClassMethods);
			}
			catch (...)
			{
				m_logger->LogError("Failed to read the optional class method list for protocol pointed to by 0x%llx",
					protocolLocation);
			}
		}
		m_protocols[protocolLocation] = protocolClass;
	}
}

void ObjCProcessor::GetRelativeMethod(ObjCReader* reader, method_t& meth)
{
	uint64_t offset = reader->GetOffset();
	meth.name = offset + reader->ReadS32();

	offset += sizeof(int32_t);
	meth.types = offset + reader->ReadS32();

	offset += sizeof(int32_t);
	meth.imp = offset + reader->ReadS32();
}

void ObjCProcessor::ReadListOfMethodLists(ObjCReader* reader, ClassBase& cls, std::string_view name, view_ptr_t start)
{
	reader->Seek(start);
	method_list_t head;
	head.entsizeAndFlags = reader->Read32();
	head.count = reader->Read32();

	if (head.count > MAX_METHOD_LIST_COUNT)
	{
		m_logger->LogError("List of method lists at 0x%llx has an invalid count of 0x%x", start, head.count);
		return;
	}

	for (size_t i = 0; i < head.count; ++i) {
		relative_list_list_entry_t list_entry;
		reader->Read(&list_entry, sizeof(list_entry));

		ReadMethodList(reader, cls, name, reader->GetOffset() - sizeof(list_entry) + list_entry.listOffset);
		// Reset the cursor to immediately past the list entry.
		reader->Seek(start + sizeof(method_list_t) + ((i + 1) * sizeof(relative_list_list_entry_t)));
	}
}

void ObjCProcessor::ReadMethodList(ObjCReader* reader, ClassBase& cls, std::string_view name, view_ptr_t start)
{
	// Lower two bits indicate the type of method list.
	switch (start & 0b11) {
		case 0:
			break;
		case 1:
			return ReadListOfMethodLists(reader, cls, name, start - 1);
		default:
			m_logger->LogDebug("ReadMethodList: Unknown method list type at 0x%llx: %d", start, start & 0x3);
			return;
	}

	reader->Seek(start);
	method_list_t head;
	head.entsizeAndFlags = reader->Read32();
	head.count = reader->Read32();

	if (head.count > MAX_METHOD_LIST_COUNT)
	{
		m_logger->LogError("Method list at 0x%llx has an invalid count of 0x%x", start, head.count);
		return;
	}

	uint64_t pointerSize = m_data->GetAddressSize();
	bool relativeOffsets = (head.entsizeAndFlags & 0xFFFF0000) & 0x80000000;
	bool directSelectors = (head.entsizeAndFlags & 0xFFFF0000) & 0x40000000;
	auto methodSize = relativeOffsets ? 12 : pointerSize * 3;
	DefineObjCSymbol(DataSymbol, m_typeNames.methodList, "method_list_" + std::string(name), start, true);

	for (unsigned i = 0; i < head.count; i++)
	{
		try
		{
			Method method;
			auto cursor = start + sizeof(method_list_t) + (i * methodSize);
			reader->Seek(cursor);
			method_t meth;
			// workflow_objc support
			uint64_t selRefAddr = 0;
			uint64_t selAddr = 0;
			// --
			if (relativeOffsets)
			{
				GetRelativeMethod(reader, meth);
			}
			else
			{
				meth.name = ReadPointerAccountingForRelocations(reader);
				meth.types = ReadPointerAccountingForRelocations(reader);
				meth.imp = ReadPointerAccountingForRelocations(reader);
			}
			if (!relativeOffsets || directSelectors)
			{
				reader->Seek(meth.name);
				selAddr = meth.name;
				method.name = reader->ReadCString();
				reader->Seek(meth.types);
				method.types = reader->ReadCString();
				DefineObjCSymbol(DataSymbol, Type::ArrayType(Type::IntegerType(1, true), method.name.size() + 1),
					"sel_" + method.name, meth.name, true);
				DefineObjCSymbol(DataSymbol, Type::ArrayType(Type::IntegerType(1, true), method.types.size() + 1),
					"selTypes_" + method.name, meth.types, true);
			}
			else
			{
				std::string sel;
				view_ptr_t selRef;
				reader->Seek(meth.name);
				selRefAddr = meth.name;
				selRef = ReadPointerAccountingForRelocations(reader);
				reader->Seek(meth.types);
				method.types = reader->ReadCString();
				selAddr = selRef;
				if (const auto& it = m_selectorCache.find(selRef); it != m_selectorCache.end())
					method.name = it->second;
				else
				{
					reader->Seek(selRef);
					method.name = reader->ReadCString();
					m_selectorCache[selRef] = method.name;
				}
				auto selType = Type::ArrayType(Type::IntegerType(1, true), method.name.size() + 1);
				DefineObjCSymbol(DataSymbol, selType, "sel_" + method.name, selRef, true);
				DefineObjCSymbol(DataSymbol, Type::ArrayType(Type::IntegerType(1, true), method.types.size() + 1),
					"selTypes_" + method.name, meth.types, true);
				DefineObjCSymbol(DataSymbol, Type::PointerType(m_data->GetAddressSize(), selType),
					"selRef_" + method.name, meth.name, true);
			}

			// workflow objc support
			if (selAddr)
				m_selToImplementations[selAddr].push_back(meth.imp);
			if (selRefAddr)
				m_selRefToImplementations[selRefAddr].push_back(meth.imp);
			// --

			DefineObjCSymbol(DataSymbol, relativeOffsets ? m_typeNames.methodEntry : m_typeNames.method,
				"method_" + method.name, cursor, true);
			method.imp = meth.imp;
			cls.methodList[cursor] = method;
			m_localMethods[cursor] = method;

			if (selAddr)
				m_data->AddDataReference(selAddr, meth.imp);
			if (selRefAddr)
				m_data->AddDataReference(selRefAddr, meth.imp);
		}
		catch (...)
		{
			m_logger->LogError(
				"Failed to process a method at offset 0x%llx", start + sizeof(method_list_t) + (i * methodSize));
		}
	}
}

void ObjCProcessor::ReadIvarList(ObjCReader* reader, ClassBase& cls, std::string_view name, view_ptr_t start)
{
	reader->Seek(start);
	ivar_list_t head;
	head.entsizeAndFlags = reader->Read32();
	head.count = reader->Read32();
	if (head.count > MAX_IVAR_LIST_COUNT)
	{
		m_logger->LogWarn("Ivar list at 0x%llx has an invalid count of 0x%x, skipping..", start, head.count);
		return;
	}
	auto addressSize = m_data->GetAddressSize();
	DefineObjCSymbol(DataSymbol, m_typeNames.ivarList, "ivar_list_" + std::string(name), start, true);
	for (unsigned i = 0; i < head.count; i++)
	{
		try
		{
			Ivar ivar;
			ivar_t ivarStruct;
			uint64_t cursor = start + (sizeof(ivar_list_t)) + (i * ((addressSize * 3) + 8));
			reader->Seek(cursor);
			ivarStruct.offset = ReadPointerAccountingForRelocations(reader);
			ivarStruct.name = ReadPointerAccountingForRelocations(reader);
			ivarStruct.type = ReadPointerAccountingForRelocations(reader);
			ivarStruct.alignmentRaw = reader->Read32();
			ivarStruct.size = reader->Read32();

			if (ivarStruct.offset)
			{
				reader->Seek(ivarStruct.offset);
				ivar.offset = reader->Read32();
			}
			else
			{
				// `offset` can be 0 if the ivar is an anonymous bitfield.
				ivar.offset = 0;
			}

			reader->Seek(ivarStruct.name);
			ivar.name = reader->ReadCString();
			reader->Seek(ivarStruct.type);
			ivar.type = reader->ReadCString();

			DefineObjCSymbol(DataSymbol, m_typeNames.ivar, "ivar_" + ivar.name, cursor, true);
			DefineObjCSymbol(DataSymbol, Type::ArrayType(Type::IntegerType(1, true), ivar.name.size() + 1),
				"ivarName_" + ivar.name, ivarStruct.name, true);
			DefineObjCSymbol(DataSymbol, Type::ArrayType(Type::IntegerType(1, true), ivar.type.size() + 1),
				"ivarType_" + ivar.name, ivarStruct.type, true);

			cls.ivarList[cursor] = ivar;
		}
		catch (...)
		{
			m_logger->LogError("Failed to process an ivar at offset 0x%llx",
				start + (sizeof(ivar_list_t)) + (i * ((addressSize * 3) + 8)));
		}
	}
}

// Returns the type named `name`, creating it via `factory()` and
// defining it on the view if it does not already exist.
template <typename F>
	requires (std::is_same_v<std::invoke_result_t<F>, Ref<Type>>)
std::pair<QualifiedName, Ref<Type>> DefineNamedType(
	Ref<BinaryView> view, const QualifiedName& name, F&& factory)
{
	auto typeID = Type::GenerateAutoTypeId("objc", name);
	if (auto type = view->GetTypeById(typeID))
		return {name, type};

	auto type = factory();
	auto definedName = view->DefineType(typeID, name, type);
	return {definedName, type};
}

std::pair<QualifiedName, Ref<Type>> finalizeStructureBuilder(
	Ref<BinaryView> m_data, StructureBuilder sb, const QualifiedName& name)
{
	return DefineNamedType(m_data, name, [&]() {
		auto classTypeStruct = sb.Finalize();
		return Type::StructureType(classTypeStruct);
	});
}

std::pair<QualifiedName, Ref<Type>> finalizeStructureBuilder(
	Ref<BinaryView> m_data, StructureBuilder sb, const std::string& name)
{
	return finalizeStructureBuilder(m_data, std::move(sb), QualifiedName(name));
}

std::pair<QualifiedName, Ref<Type>> finalizeEnumerationBuilder(
	Ref<BinaryView> m_data, EnumerationBuilder eb, uint64_t size, const QualifiedName& name)
{
	return DefineNamedType(m_data, name, [&]() {
		auto enumTypeStruct = eb.Finalize();
		return Type::EnumerationType(enumTypeStruct, size);
	});
}

inline QualifiedName defineTypedef(Ref<BinaryView> m_data, const QualifiedName& name, Ref<Type> type)
{
	return DefineNamedType(m_data, name, [&]() {
		return type;
	}).first;
}

void ObjCProcessor::GenerateClassTypes()
{
	for (auto& [_, cls] : m_classes)
	{
		QualifiedName classTypeName = cls.name;
		std::string classTypeId = Type::GenerateAutoTypeId("objc", classTypeName);
		if (m_data->GetTypeById(classTypeId))
			continue;

		QualifiedName typeName;
		StructureBuilder classTypeBuilder;
		bool failedToDecodeType = false;
		for (const auto& [ivarLoc, ivar] : cls.instanceClass.ivarList)
		{
			auto encodedTypeList = ParseEncodedType(ivar.type);
			if (encodedTypeList.empty())
			{
				failedToDecodeType = true;
				break;
			}
			auto encodedType = encodedTypeList.at(0);

			Ref<Type> type;

			if (encodedType.type)
				type = encodedType.type;
			else
			{
				type = Type::NamedType(encodedType.name, Type::PointerType(m_data->GetAddressSize(), Type::VoidType()));
				for (size_t i = encodedType.ptrCount; i > 0; i--)
					type = Type::PointerType(m_data->GetAddressSize(), type);
			}

			if (!type)
				type = Type::PointerType(m_data->GetAddressSize(), Type::VoidType());

			classTypeBuilder.AddMemberAtOffset(type, ivar.name, ivar.offset);
		}
		if (failedToDecodeType)
			continue;
		auto classTypeStruct = classTypeBuilder.Finalize();
		Ref<Type> classType = Type::StructureType(classTypeStruct);
		QualifiedName classQualName = m_data->DefineType(classTypeId, classTypeName, classType);
		cls.associatedName = classTypeName;
	}
}

bool ObjCProcessor::ApplyMethodType(Class& cls, Method& method, bool isInstanceMethod)
{
	if (!method.imp || !m_data->IsValidOffset(method.imp)) {
		return false;
	}

	std::stringstream r(method.name);

	std::string token;
	std::vector<std::string> selectorTokens;
	while (std::getline(r, token, ':'))
		selectorTokens.push_back(token);

	std::vector<QualifiedNameOrType> typeTokens = ParseEncodedType(method.types);
	if (typeTokens.empty())
		return false;

	auto typeForQualifiedNameOrType = [this](QualifiedNameOrType nameOrType) {
		Ref<Type> type;

		if (nameOrType.type)
		{
			type = nameOrType.type;
			if (!type)
				type = Type::PointerType(m_data->GetAddressSize(), Type::VoidType());
		}
		else
		{
			type = Type::NamedType(nameOrType.name, Type::PointerType(m_data->GetAddressSize(), Type::VoidType()));
			for (size_t i = nameOrType.ptrCount; i > 0; i--)
				type = Type::PointerType(m_data->GetAddressSize(), type);
		}

		return type;
	};

	BinaryNinja::QualifiedNameAndType nameAndType;
	std::set<BinaryNinja::QualifiedName> typesAllowRedefinition;

	auto retType = typeForQualifiedNameOrType(typeTokens[0]);

	std::vector<BinaryNinja::FunctionParameter> params;
	auto cc = m_data->GetDefaultPlatform()->GetDefaultCallingConvention();

	params.push_back({"self",
		cls.associatedName.IsEmpty() ?
			m_types.id :
			Type::PointerType(m_data->GetAddressSize(), Type::NamedType(m_data, cls.associatedName)),
		DefaultLocationSource, BinaryNinja::Variable()});

	params.push_back({"sel", m_types.sel, DefaultLocationSource, BinaryNinja::Variable()});

	for (size_t i = 3; i < typeTokens.size(); i++)
	{
		std::string name;
		if (selectorTokens.size() > i - 3)
			name = ArgumentNameFromSelectorComponent(selectorTokens[i - 3]);
		else
			name = "arg";

		params.push_back({std::move(name), typeForQualifiedNameOrType(typeTokens[i]), DefaultLocationSource, BinaryNinja::Variable()});
	}

	auto funcType = BinaryNinja::Type::FunctionType(retType, cc, params);

	// Search for the method's implementation function; apply the type if found.
	std::string prefix = isInstanceMethod ? "-" : "+";
	auto name = prefix + "[" + cls.name + " " + method.name + "]";

	DefineObjCSymbol(FunctionSymbol, funcType, name, method.imp, true);

	return true;
}

void ObjCProcessor::ApplyMethodTypes(Class& cls)
{
	for (auto& [_, method] : cls.instanceClass.methodList)
	{
		ApplyMethodType(cls, method, true);
	}
	for (auto& [_, method] : cls.metaClass.methodList)
	{
		ApplyMethodType(cls, method, false);
	}
}

Ref<Section> ObjCProcessor::GetSectionWithName(const char* sectionName)
{
	return m_data->GetSectionByName(sectionName);
}

void ObjCProcessor::PostProcessObjCSections(ObjCReader* reader)
{
	auto ptrSize = m_data->GetAddressSize();
	if (auto imageInfo = GetSectionWithName("__objc_imageinfo"))
	{
		auto start = imageInfo->GetStart();
		auto type = Type::NamedType(m_data, m_typeNames.imageInfo);
		m_data->DefineDataVariable(start, type);
	}
	if (auto selrefs = GetSectionWithName("__objc_selrefs"))
	{
		auto start = selrefs->GetStart();
		auto end = selrefs->GetEnd();
		auto type = Type::PointerType(ptrSize, Type::IntegerType(1, false));
		for (view_ptr_t i = start; i < end; i += ptrSize)
		{
			reader->Seek(i);
			auto selLoc = ReadPointerAccountingForRelocations(reader);
			std::string sel;
			if (const auto& it = m_selectorCache.find(selLoc); it != m_selectorCache.end())
				sel = it->second;
			else
			{
				reader->Seek(selLoc);
				sel = reader->ReadCString();
				m_selectorCache[selLoc] = sel;
				DefineObjCSymbol(DataSymbol, Type::ArrayType(Type::IntegerType(1, true), sel.size() + 1), "sel_" + sel,
					selLoc, true);
			}
			DefineObjCSymbol(DataSymbol, type, "selRef_" + sel, i, true);
		}
	}
	if (auto superRefs = GetSectionWithName("__objc_classrefs"))
	{
		auto start = superRefs->GetStart();
		auto end = superRefs->GetEnd();
		auto type = Type::PointerType(ptrSize, Type::NamedType(m_data, m_typeNames.cls));
		for (view_ptr_t i = start; i < end; i += ptrSize)
		{
			if (auto className = ClassNameForTargetOfPointerAt(reader, i))
				DefineObjCSymbol(DataSymbol, type, "clsRef_" + *className, i, true);
		}
	}
	if (auto superRefs = GetSectionWithName("__objc_superrefs"))
	{
		auto start = superRefs->GetStart();
		auto end = superRefs->GetEnd();
		auto type = Type::PointerType(ptrSize, Type::NamedType(m_data, m_typeNames.cls));
		for (view_ptr_t i = start; i < end; i += ptrSize)
		{
			reader->Seek(i);
			auto clsLoc = ReadPointerAccountingForRelocations(reader);
			if (const auto& it = m_classes.find(clsLoc); it != m_classes.end())
			{
				auto& cls = it->second;
				std::string name = cls.name;
				if (!name.empty())
					DefineObjCSymbol(DataSymbol, type, "superRef_" + name, i, true);
			}
		}
	}
	if (auto protoRefs = GetSectionWithName("__objc_protorefs"))
	{
		auto start = protoRefs->GetStart();
		auto end = protoRefs->GetEnd();
		auto type = Type::PointerType(ptrSize, Type::NamedType(m_data, m_typeNames.protocol));
		for (view_ptr_t i = start; i < end; i += ptrSize)
		{
			reader->Seek(i);
			auto protoLoc = ReadPointerAccountingForRelocations(reader);
			if (const auto& it = m_protocols.find(protoLoc); it != m_protocols.end())
			{
				auto& proto = it->second;
				std::string name = proto.name;
				if (!name.empty())
					DefineObjCSymbol(DataSymbol, type, "protoRef_" + name, i, true);
			}
		}
	}
	if (auto ivars = GetSectionWithName("__objc_ivar"))
	{
		auto start = ivars->GetStart();
		auto end = ivars->GetEnd();
		// The ivar section contains entries of type `long` for for all architectures
		// except arm64, which uses `int` for the ivar offset.
		size_t ivarOffsetSize = m_data->GetDefaultArchitecture()->GetName() == "aarch64" ? 4 : ptrSize;
		TypeBuilder ivarSectionEntryTypeBuilder(Type::IntegerType(ivarOffsetSize, false));
		ivarSectionEntryTypeBuilder.SetConst(true);
		auto type = ivarSectionEntryTypeBuilder.Finalize();
		for (view_ptr_t i = start; i < end; i += ivarOffsetSize)
		{
			m_data->DefineDataVariable(i, type);
		}
	}
}

uint64_t ObjCProcessor::ReadPointerAccountingForRelocations(ObjCReader* reader)
{
	if (auto it = m_relocationPointerRewrites.find(reader->GetOffset()); it != m_relocationPointerRewrites.end())
	{
		reader->SeekRelative(m_data->GetAddressSize());
		return it->second;
	}
	return reader->ReadPointer();
}


ObjCProcessor::ObjCProcessor(BinaryView* data, const char* loggerName, bool skipClassBaseProtocols) :
	 m_skipClassBaseProtocols(skipClassBaseProtocols), m_data(data)
{
	m_logger = m_data->CreateLogger(loggerName);

	m_types.id = NamedType("id");
	m_types.sel = NamedType("SEL");
	m_types.BOOL = NamedType("BOOL");
}

uint64_t ObjCProcessor::GetObjCRelativeMethodBaseAddress(ObjCReader* reader)
{
	return 0;
}

Ref<Symbol> ObjCProcessor::GetSymbol(uint64_t address)
{
	return m_data->GetSymbolByAddress(address);
}

void ObjCProcessor::ProcessObjCData()
{
	auto guard = ScopedSymbolQueue::Make();

	auto addrSize = m_data->GetAddressSize();
	m_typeNames.nsInteger = defineTypedef(m_data, {"NSInteger"}, Type::IntegerType(addrSize, true));
	m_typeNames.nsuInteger = defineTypedef(m_data, {"NSUInteger"}, Type::IntegerType(addrSize, false));
	m_typeNames.cgFloat = defineTypedef(m_data, {"CGFloat"}, Type::FloatType(addrSize));

	BNPointerBaseType relativeSelectorBaseType = RelativeToVariableAddressPointerBaseType;
	uint64_t relativeSelectorBaseOffset = 0;
	auto reader = GetReader();
	if (auto objCRelativeMethodsBaseAddr = GetObjCRelativeMethodBaseAddress(reader.get())) {
		m_logger->LogDebug("RelativeMethodSelector Base: 0x%llx", objCRelativeMethodsBaseAddr);
		relativeSelectorBaseType = RelativeToConstantPointerBaseType;
		relativeSelectorBaseOffset = objCRelativeMethodsBaseAddr;
	}

	auto relativeSelectorPtrName = defineTypedef(m_data, {"rel_SEL"},
		TypeBuilder::PointerType(4, Type::PointerType(addrSize, Type::IntegerType(1, false)))
			.SetPointerBase(relativeSelectorBaseType, relativeSelectorBaseOffset)
			.Finalize());
	auto relativeCharPtrName = defineTypedef(m_data, {"rel_cstr"},
		TypeBuilder::PointerType(4, Type::PointerType(addrSize, Type::IntegerType(1, false)))
			.SetPointerBase(RelativeToVariableAddressPointerBaseType, 0)
			.Finalize());
	auto relativeIMPPtrName = defineTypedef(m_data, {"rel_IMP"},
		TypeBuilder::PointerType(4, Type::VoidType())
			.SetPointerBase(RelativeToVariableAddressPointerBaseType, 0)
			.Finalize());

	// https://github.com/apple-oss-distributions/objc4/blob/196363c165b175ed925ef6b9b99f558717923c47/runtime/objc-abi.h
	EnumerationBuilder imageInfoFlagBuilder;
	imageInfoFlagBuilder.AddMemberWithValue("IsReplacement", 1 << 0);
	imageInfoFlagBuilder.AddMemberWithValue("SupportsGC", 1 << 1);
	imageInfoFlagBuilder.AddMemberWithValue("RequiresGC", 1 << 2);
	imageInfoFlagBuilder.AddMemberWithValue("OptimizedByDyld", 1 << 3);
	imageInfoFlagBuilder.AddMemberWithValue("CorrectedSynthesize", 1 << 4);
	imageInfoFlagBuilder.AddMemberWithValue("IsSimulated", 1 << 5);
	imageInfoFlagBuilder.AddMemberWithValue("HasCategoryClassProperties", 1 << 6);
	imageInfoFlagBuilder.AddMemberWithValue("OptimizedByDyldClosure", 1 << 7);
	imageInfoFlagBuilder.AddMemberWithValue("SwiftUnstableVersionMask", 0xff << 8);
	imageInfoFlagBuilder.AddMemberWithValue("SwiftStableVersionMask", 0xFFFF << 16);
	auto imageInfoFlagType = finalizeEnumerationBuilder(m_data, imageInfoFlagBuilder, 4, {"objc_image_info_flags"});
	m_typeNames.imageInfoFlags = imageInfoFlagType.first;

	EnumerationBuilder swiftVersionBuilder;
	swiftVersionBuilder.AddMemberWithValue("SwiftVersion1", 1);
	swiftVersionBuilder.AddMemberWithValue("SwiftVersion1_2", 2);
	swiftVersionBuilder.AddMemberWithValue("SwiftVersion2", 3);
	swiftVersionBuilder.AddMemberWithValue("SwiftVersion3", 4);
	swiftVersionBuilder.AddMemberWithValue("SwiftVersion4", 5);
	swiftVersionBuilder.AddMemberWithValue("SwiftVersion4_1", 6);  // [sic]
	swiftVersionBuilder.AddMemberWithValue("SwiftVersion4_2", 6);
	swiftVersionBuilder.AddMemberWithValue("SwiftVersion5", 7);
	auto swiftVersionType =
		finalizeEnumerationBuilder(m_data, swiftVersionBuilder, 4, {"objc_image_info_swift_version"});
	m_typeNames.imageInfoSwiftVersion = swiftVersionType.first;

	StructureBuilder imageInfoBuilder;
	imageInfoBuilder.AddMember(Type::IntegerType(4, false), "version");
	imageInfoBuilder.AddMember(Type::NamedType(m_data, m_typeNames.imageInfoFlags), "flags");
	auto imageInfoType = finalizeStructureBuilder(m_data, imageInfoBuilder, "objc_image_info_t");
	m_typeNames.imageInfo = imageInfoType.first;

	StructureBuilder methodEntry;
	methodEntry.AddMember(Type::NamedType(m_data, relativeSelectorPtrName), "name");
	methodEntry.AddMember(Type::NamedType(m_data, relativeCharPtrName), "types");
	methodEntry.AddMember(Type::NamedType(m_data, relativeIMPPtrName), "imp");
	auto type = finalizeStructureBuilder(m_data, methodEntry, "objc_method_entry_t");
	m_typeNames.methodEntry = type.first;

	StructureBuilder method;
	method.AddMember(Type::PointerType(addrSize, Type::IntegerType(1, true)), "name");
	method.AddMember(Type::PointerType(addrSize, Type::IntegerType(1, true)), "types");
	method.AddMember(Type::PointerType(addrSize, Type::VoidType()), "imp");
	type = finalizeStructureBuilder(m_data, method, "objc_method_t");
	m_typeNames.method = type.first;

	StructureBuilder methList;
	methList.AddMember(Type::IntegerType(4, false), "obsolete");
	methList.AddMember(Type::IntegerType(4, false), "count");
	type = finalizeStructureBuilder(m_data, methList, "objc_method_list_t");
	m_typeNames.methodList = type.first;

	StructureBuilder ivarBuilder;
	ivarBuilder.AddMember(Type::PointerType(addrSize, Type::IntegerType(4, false)), "offset");
	ivarBuilder.AddMember(Type::PointerType(addrSize, Type::IntegerType(1, true)), "name");
	ivarBuilder.AddMember(Type::PointerType(addrSize, Type::IntegerType(1, true)), "type");
	ivarBuilder.AddMember(Type::IntegerType(4, false), "alignment");
	ivarBuilder.AddMember(Type::IntegerType(4, false), "size");
	type = finalizeStructureBuilder(m_data, ivarBuilder, "objc_ivar_t");
	m_typeNames.ivar = type.first;

	StructureBuilder ivarList;
	ivarList.AddMember(Type::IntegerType(4, false), "entsize");
	ivarList.AddMember(Type::IntegerType(4, false), "count");
	type = finalizeStructureBuilder(m_data, ivarList, "objc_ivar_list_t");
	m_typeNames.ivarList = type.first;

	StructureBuilder protocolListBuilder;
	protocolListBuilder.AddMember(Type::IntegerType(addrSize, false), "count");
	m_typeNames.protocolList = finalizeStructureBuilder(m_data, protocolListBuilder, "objc_protocol_list_t").first;

	StructureBuilder classROBuilder;
	classROBuilder.AddMember(Type::IntegerType(4, false), "flags");
	classROBuilder.AddMember(Type::IntegerType(4, false), "start");
	classROBuilder.AddMember(Type::IntegerType(4, false), "size");
	if (addrSize == 8)
		classROBuilder.AddMember(Type::IntegerType(4, false), "reserved");
	classROBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "ivar_layout");
	classROBuilder.AddMember(Type::PointerType(addrSize, Type::IntegerType(1, true)), "name");
	classROBuilder.AddMember(Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.methodList)), "methods");
	classROBuilder.AddMember(
		Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.protocolList)), "protocols");
	classROBuilder.AddMember(Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.ivarList)), "ivars");
	classROBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "weak_ivar_layout");
	classROBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "properties");
	type = finalizeStructureBuilder(m_data, classROBuilder, "objc_class_ro_t");
	m_typeNames.classRO = type.first;

	QualifiedName classTypeName("objc_class_t");
	auto classTypeId = Type::GenerateAutoTypeId("objc", classTypeName);
	auto isaType = Type::PointerType(m_data->GetDefaultArchitecture(),
		TypeBuilder::NamedType(
			new NamedTypeReferenceBuilder(StructNamedTypeClass, "", classTypeName), m_data->GetAddressSize(), 4)
			.Finalize());

	StructureBuilder classBuilder;
	classBuilder.AddMember(isaType, "isa");
	classBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "super");
	classBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "cache");
	classBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "vtable");
	classBuilder.AddMember(Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.classRO)), "data");

	type = finalizeStructureBuilder(m_data, classBuilder, classTypeName);
	m_typeNames.cls = type.first;

	StructureBuilder categoryBuilder;
	categoryBuilder.AddMember(Type::PointerType(addrSize, Type::IntegerType(1, true)), "category_name");
	categoryBuilder.AddMember(Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.cls)), "class");
	categoryBuilder.AddMember(
		Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.methodList)), "inst_methods");
	categoryBuilder.AddMember(
		Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.methodList)), "class_methods");
	categoryBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "protocols");
	categoryBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "properties");
	m_typeNames.category = finalizeStructureBuilder(m_data, categoryBuilder, "objc_category_t").first;

	StructureBuilder protocolBuilder;
	protocolBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "isa");
	protocolBuilder.AddMember(Type::PointerType(addrSize, Type::IntegerType(1, true)), "mangledName");
	protocolBuilder.AddMember(
		Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.protocolList)), "protocols");
	protocolBuilder.AddMember(
		Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.methodList)), "instanceMethods");
	protocolBuilder.AddMember(
		Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.methodList)), "classMethods");
	protocolBuilder.AddMember(
		Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.methodList)), "optionalInstanceMethods");
	protocolBuilder.AddMember(
		Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.methodList)), "optionalClassMethods");
	protocolBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "instanceProperties");
	protocolBuilder.AddMember(Type::IntegerType(4, false), "size");
	protocolBuilder.AddMember(Type::IntegerType(4, false), "flags");
	m_typeNames.protocol = finalizeStructureBuilder(m_data, protocolBuilder, "objc_protocol_t").first;

	BulkSymbolModification bulkSymbolModification(m_data);
	if (auto classList = GetSectionWithName("__objc_classlist"))
		LoadClasses(reader.get(), classList);
	if (auto nonLazyClassList = GetSectionWithName("__objc_nlclslist"))
		LoadClasses(reader.get(), nonLazyClassList);  // See: https://stackoverflow.com/a/15318325

	GenerateClassTypes();
	for (auto& [_, cls] : m_classes)
		ApplyMethodTypes(cls);

	if (auto catList = GetSectionWithName("__objc_catlist"))  // Do this after loading class type data.
		LoadCategories(reader.get(), catList);
	if (auto nonLazyCatList = GetSectionWithName("__objc_nlcatlist"))  // Do this after loading class type data.
		LoadCategories(reader.get(), nonLazyCatList);
	for (auto& [_, cat] : m_categories)
		ApplyMethodTypes(cat);

	if (auto protoList = GetSectionWithName("__objc_protolist"))
		LoadProtocols(reader.get(), protoList);

	PostProcessObjCSections(reader.get());

	ScopedSymbolQueue::Get().Process();

	auto meta = SerializeMetadata();
	m_data->StoreMetadata("Objective-C", meta, true);

	m_relocationPointerRewrites.clear();
}

void ObjCProcessor::ProcessObjCLiterals()
{
	ProcessCFStrings();
	ProcessNSConstantArrays();
	ProcessNSConstantDictionaries();
	ProcessNSConstantIntegerNumbers();
	ProcessNSConstantFloatingPointNumbers();
	ProcessNSConstantDatas();
}

void ObjCProcessor::ProcessCFStrings()
{
	auto guard = ScopedSymbolQueue::Make();

	uint64_t ptrSize = m_data->GetAddressSize();
	// https://github.com/apple/llvm-project/blob/next/clang/lib/CodeGen/CodeGenModule.cpp#L6129
	// See also ASTContext.cpp ctrl+f __NSConstantString_tag

	// The place these flags are used is unclear, along with any clear flag definitions, but they are useful for
	// introspection
	EnumerationBuilder __cfStringFlagBuilder;
	__cfStringFlagBuilder.AddMemberWithValue("SwiftABI", 0b1);
	__cfStringFlagBuilder.AddMemberWithValue("Swift4_1", 0b100);
	// LLVM also sets 0x7c0 (0b11111000000) on both UTF8 and UTF16 strings however it is unclear what this denotes.
	__cfStringFlagBuilder.AddMemberWithValue("UTF8", 0b1000);
	__cfStringFlagBuilder.AddMemberWithValue("UTF16", 0b10000);
	auto type = finalizeEnumerationBuilder(m_data, __cfStringFlagBuilder, ptrSize, {"CFStringFlag"});
	m_typeNames.cfStringFlag = type.first;

	StructureBuilder __cfStringStructBuilder;
	__cfStringStructBuilder.AddMember(Type::PointerType(ptrSize, Type::VoidType()), "isa");
	__cfStringStructBuilder.AddMember(Type::NamedType(m_data, m_typeNames.cfStringFlag), "flags");
	__cfStringStructBuilder.AddMember(Type::PointerType(ptrSize, Type::IntegerType(1, true)), "data");
	__cfStringStructBuilder.AddMember(Type::IntegerType(ptrSize, false), "length");
	type = finalizeStructureBuilder(m_data, __cfStringStructBuilder, "__NSConstantString");
	m_typeNames.cfString = type.first;

	StructureBuilder __cfStringUTF16StructBuilder;
	__cfStringUTF16StructBuilder.AddMember(Type::PointerType(ptrSize, Type::VoidType()), "isa");
	__cfStringUTF16StructBuilder.AddMember(Type::NamedType(m_data, m_typeNames.cfStringFlag), "flags");
	__cfStringUTF16StructBuilder.AddMember(Type::PointerType(ptrSize, Type::IntegerType(2, true)), "data");
	__cfStringUTF16StructBuilder.AddMember(Type::IntegerType(ptrSize, false), "length");
	type = finalizeStructureBuilder(m_data, __cfStringUTF16StructBuilder, "__NSConstantString_UTF16");
	m_typeNames.cfStringUTF16 = type.first;

	auto reader = GetReader();
	if (auto cfstrings = GetSectionWithName("__cfstring"))
	{
		auto start = cfstrings->GetStart();
		auto end = cfstrings->GetEnd();
		auto typeWidth = Type::NamedType(m_data, m_typeNames.cfString)->GetWidth();
		BulkSymbolModification bulkSymbolModification(m_data);
		for (view_ptr_t i = start; i < end; i += typeWidth)
		{
			reader->Seek(i + ptrSize);
			uint64_t flags = reader->ReadPointer();
			auto strLoc = ReadPointerAccountingForRelocations(reader.get());
			auto size = reader->ReadPointer();
			if (size > cfstrings->GetEnd() || reader->GetOffset() > cfstrings->GetEnd() - size)
			{
				m_logger->LogWarn("CFString at 0x%llx has invalid size 0x%llx, skipping...", i, size);
				continue;
			}
			std::string str;
			if (flags & 0b10000)  // UTF16
			{
				auto data = m_data->ReadBuffer(strLoc, size * 2);

				str = "";
				for (uint64_t bufferOff = 0; bufferOff + 1 < data.GetLength(); bufferOff += 2)
				{
					uint8_t* rawData = static_cast<uint8_t*>(data.GetData());
					uint8_t* offsetAddress = rawData + bufferOff;
					uint16_t c = *reinterpret_cast<uint16_t*>(offsetAddress);
					if (c == 0x20) {
						str.push_back('_');
					} else if (c == '\r') {
						str.push_back('\\');
						str.push_back('r');
					} else if (c == '\n') {
						str.push_back('\\');
						str.push_back('n');
					} else if (c == '\t') {
						str.push_back('\\');
						str.push_back('t');
					} else if (c > 0x20 && c < 0x80) {
						str.push_back(c);
					} else {
						str.push_back('?');
					}
				}
				DefineObjCSymbol(
					DataSymbol, Type::ArrayType(Type::WideCharType(2), size + 1), "ustr_" + str, strLoc, true);
				DefineObjCSymbol(
					DataSymbol, Type::NamedType(m_data, m_typeNames.cfStringUTF16), "cfstr_" + str, i, true);
			}
			else  // UTF8 / ASCII
			{
				reader->Seek(strLoc);
				std::string rawStr = reader->ReadCString(size + 1);
				str = "";
				for (signed char c : rawStr)
				{
					if (c == 0x20) {
						str.push_back('_');
					} else if (c == '\r') {
						str.push_back('\\');
						str.push_back('r');
					} else if (c == '\n') {
						str.push_back('\\');
						str.push_back('n');
					} else if (c == '\t') {
						str.push_back('\\');
						str.push_back('t');
					} else if (c > 0x20 || c < 0) {
						str.push_back(c);
					} else {
						str.push_back('?');
					}
				}
				DefineObjCSymbol(DataSymbol, Type::ArrayType(Type::IntegerType(1, true), str.size() + 1), "cstr_" + str,
					strLoc, true);
				DefineObjCSymbol(DataSymbol, Type::NamedType(m_data, m_typeNames.cfString), "cfstr_" + str, i, true);
			}
		}

		ScopedSymbolQueue::Get().Process();
	}
}

void ObjCProcessor::ProcessNSConstantArrays()
{
	auto guard = ScopedSymbolQueue::Make();
	uint64_t ptrSize = m_data->GetAddressSize();

	StructureBuilder nsConstantArrayBuilder;
	nsConstantArrayBuilder.AddMember(Type::PointerType(ptrSize, Type::VoidType()), "isa");
	nsConstantArrayBuilder.AddMember(Type::IntegerType(ptrSize, false), "count");
	nsConstantArrayBuilder.AddMember(Type::PointerType(ptrSize, m_types.id), "objects");
	auto type = finalizeStructureBuilder(m_data, nsConstantArrayBuilder, "__NSConstantArray");
	m_typeNames.nsConstantArray = type.first;

	auto reader = GetReader();
	if (auto arrays = GetSectionWithName("__objc_arrayobj"))
	{
		auto start = arrays->GetStart();
		auto end = arrays->GetEnd();
		auto typeWidth = Type::NamedType(m_data, m_typeNames.nsConstantArray)->GetWidth();
		BulkSymbolModification bulkSymbolModification(m_data);
		for (view_ptr_t i = start; i < end; i += typeWidth)
		{
			reader->Seek(i + ptrSize);
			uint64_t count = reader->ReadPointer();
			auto dataLoc = ReadPointerAccountingForRelocations(reader.get());
			DefineObjCSymbol(
				DataSymbol, Type::ArrayType(m_types.id, count), fmt::format("nsarray_{:x}_data", i), dataLoc, true);
			DefineObjCSymbol(DataSymbol, Type::NamedType(m_data, m_typeNames.nsConstantArray),
				fmt::format("nsarray_{:x}", i), i, true);
		}
		ScopedSymbolQueue::Get().Process();
	}

}

void ObjCProcessor::ProcessNSConstantDictionaries()
{
	auto guard = ScopedSymbolQueue::Make();
	uint64_t ptrSize = m_data->GetAddressSize();

	StructureBuilder nsConstantDictionaryBuilder;
	nsConstantDictionaryBuilder.AddMember(Type::PointerType(ptrSize, Type::VoidType()), "isa");
	nsConstantDictionaryBuilder.AddMember(Type::IntegerType(ptrSize, false), "options");
	nsConstantDictionaryBuilder.AddMember(Type::IntegerType(ptrSize, false), "count");
	nsConstantDictionaryBuilder.AddMember(Type::PointerType(ptrSize, m_types.id), "keys");
	nsConstantDictionaryBuilder.AddMember(Type::PointerType(ptrSize, m_types.id), "objects");
	auto type = finalizeStructureBuilder(m_data, nsConstantDictionaryBuilder, "__NSConstantDictionary");
	m_typeNames.nsConstantDictionary = type.first;

	auto reader = GetReader();
	if (auto dicts = GetSectionWithName("__objc_dictobj"))
	{
		auto start = dicts->GetStart();
		auto end = dicts->GetEnd();
		auto typeWidth = Type::NamedType(m_data, m_typeNames.nsConstantDictionary)->GetWidth();
		BulkSymbolModification bulkSymbolModification(m_data);
		for (view_ptr_t i = start; i < end; i += typeWidth)
		{
			reader->Seek(i + (ptrSize * 2));
			// TODO: Do we need to do anything with `options`? It appears to always be 1.
			uint64_t count = reader->ReadPointer();
			auto keysLoc = ReadPointerAccountingForRelocations(reader.get());
			auto objectsLoc = ReadPointerAccountingForRelocations(reader.get());
			DefineObjCSymbol(
				DataSymbol, Type::ArrayType(m_types.id, count), fmt::format("nsdict_{:x}_keys", i), keysLoc, true);
			DefineObjCSymbol(DataSymbol, Type::ArrayType(m_types.id, count), fmt::format("nsdict_{:x}_objects", i),
				objectsLoc, true);
			DefineObjCSymbol(DataSymbol, Type::NamedType(m_data, m_typeNames.nsConstantDictionary),
				fmt::format("nsdict_{:x}", i), i, true);
		}
		ScopedSymbolQueue::Get().Process();
	}
}

void ObjCProcessor::ProcessNSConstantIntegerNumbers()
{
	auto guard = ScopedSymbolQueue::Make();
	uint64_t ptrSize = m_data->GetAddressSize();

	StructureBuilder nsConstantIntegerNumberBuilder;
	nsConstantIntegerNumberBuilder.AddMember(Type::PointerType(ptrSize, Type::VoidType()), "isa");
	nsConstantIntegerNumberBuilder.AddMember(Type::PointerType(ptrSize, Type::IntegerType(1, true)), "encoding");
	nsConstantIntegerNumberBuilder.AddMember(Type::IntegerType(ptrSize, true), "value");
	auto type = finalizeStructureBuilder(m_data, nsConstantIntegerNumberBuilder, "__NSConstantIntegerNumber");
	m_typeNames.nsConstantIntegerNumber = type.first;

	auto reader = GetReader();
	if (auto numbers = GetSectionWithName("__objc_intobj"))
	{
		auto start = numbers->GetStart();
		auto end = numbers->GetEnd();
		auto typeWidth = Type::NamedType(m_data, m_typeNames.nsConstantIntegerNumber)->GetWidth();
		BulkSymbolModification bulkSymbolModification(m_data);
		for (view_ptr_t i = start; i < end; i += typeWidth)
		{
			reader->Seek(i + ptrSize);
			uint64_t encodingLoc = ReadPointerAccountingForRelocations(reader.get());
			uint64_t value = reader->Read64();
			reader->Seek(encodingLoc);
			uint8_t encoding = reader->Read8();

			switch (encoding)
			{
			case 'c':
			case 's':
			case 'i':
			case 'l':
			case 'q':
				DefineObjCSymbol(DataSymbol, Type::NamedType(m_data, m_typeNames.nsConstantIntegerNumber),
					fmt::format("nsint_{:x}_{}", i, (int64_t)value), i, true);
				break;
			case 'C':
			case 'S':
			case 'I':
			case 'L':
			case 'Q':
				DefineObjCSymbol(DataSymbol, Type::NamedType(m_data, m_typeNames.nsConstantIntegerNumber),
					fmt::format("nsint_{:x}_{}", i, value), i, true);
				break;
			default:
				m_logger->LogWarn("Unknown type encoding '%c' in number literal object at %p", encoding, i);
				continue;
			}
		}
		ScopedSymbolQueue::Get().Process();
	}
}

void ObjCProcessor::ProcessNSConstantFloatingPointNumbers()
{
	uint64_t ptrSize = m_data->GetAddressSize();

	StructureBuilder nsConstantFloatNumberBuilder;
	nsConstantFloatNumberBuilder.AddMember(Type::PointerType(ptrSize, Type::VoidType()), "isa");
	nsConstantFloatNumberBuilder.AddMember(Type::FloatType(4), "value");
	auto type = finalizeStructureBuilder(m_data, nsConstantFloatNumberBuilder, "__NSConstantFloatNumber");
	m_typeNames.nsConstantFloatNumber = type.first;

	StructureBuilder nsConstantDoubleNumberBuilder;
	nsConstantDoubleNumberBuilder.AddMember(Type::PointerType(ptrSize, Type::VoidType()), "isa");
	nsConstantDoubleNumberBuilder.AddMember(Type::FloatType(8), "value");
	type = finalizeStructureBuilder(m_data, nsConstantDoubleNumberBuilder, "__NSConstantDoubleNumber");
	m_typeNames.nsConstantDoubleNumber = type.first;

	StructureBuilder nsConstantDateBuilder;
	nsConstantDateBuilder.AddMember(Type::PointerType(ptrSize, Type::VoidType()), "isa");
	nsConstantDateBuilder.AddMember(Type::FloatType(8), "ti");
	type = finalizeStructureBuilder(m_data, nsConstantDateBuilder, "__NSConstantDate");
	m_typeNames.nsConstantDate = type.first;

	enum SectionType
	{
		Float,
		Double,
		Date,
	};

	constexpr std::pair<std::string_view, SectionType> sections[] = {
		{"__objc_floatobj", Float},
		{"__objc_doubleobj", Double},
		{"__objc_dateobj", Date},
	};

	auto reader = GetReader();
	for (auto& [sectionName, sectionType] : sections)
	{
		auto numbers = GetSectionWithName(sectionName.data());
		if (!numbers)
			continue;

		auto guard = ScopedSymbolQueue::Make();
		auto start = numbers->GetStart();
		auto end = numbers->GetEnd();
		auto typeWidth = Type::NamedType(m_data, m_typeNames.nsConstantDoubleNumber)->GetWidth();
		BulkSymbolModification bulkSymbolModification(m_data);
		for (view_ptr_t i = start; i < end; i += typeWidth)
		{
			reader->Seek(i + ptrSize);

			QualifiedName* typeName = nullptr;
			std::string name;

			switch (sectionType)
			{
			case Float:
			{
				float value = 0;
				reader->Read(&value, sizeof(value));
				name = fmt::format("nsfloat_{:x}_{}", i, value);
				typeName = &m_typeNames.nsConstantFloatNumber;
				break;
			}
			case Double:
			{
				double value = 0;
				reader->Read(&value, sizeof(value));
				name = fmt::format("nsdouble_{:x}_{}", i, value);
				typeName = &m_typeNames.nsConstantDoubleNumber;
				break;
			}
			case Date:
			{
				double value = 0;
				reader->Read(&value, sizeof(value));
				name = fmt::format("nsdate_{:x}_{}", i, value);
				typeName = &m_typeNames.nsConstantDate;
				break;
			}
			}
			DefineObjCSymbol(DataSymbol, Type::NamedType(m_data, *typeName), name, i, true);
		}
		ScopedSymbolQueue::Get().Process();
	}
}

void ObjCProcessor::ProcessNSConstantDatas()
{
	auto guard = ScopedSymbolQueue::Make();
	uint64_t ptrSize = m_data->GetAddressSize();

	StructureBuilder nsConstantDataBuilder;
	nsConstantDataBuilder.AddMember(Type::PointerType(ptrSize, Type::VoidType()), "isa");
	nsConstantDataBuilder.AddMember(Type::IntegerType(ptrSize, false), "length");
	nsConstantDataBuilder.AddMember(Type::PointerType(ptrSize, Type::IntegerType(1, false)), "bytes");
	auto type = finalizeStructureBuilder(m_data, nsConstantDataBuilder, "__NSConstantData");
	m_typeNames.nsConstantData = type.first;

	auto reader = GetReader();
	if (auto datas = GetSectionWithName("__objc_dataobj"))
	{
		auto start = datas->GetStart();
		auto end = datas->GetEnd();
		auto typeWidth = Type::NamedType(m_data, m_typeNames.nsConstantData)->GetWidth();
		BulkSymbolModification bulkSymbolModification(m_data);
		for (view_ptr_t i = start; i < end; i += typeWidth)
		{
			reader->Seek(i + ptrSize);
			uint64_t length = reader->ReadPointer();
			auto dataLoc = ReadPointerAccountingForRelocations(reader.get());
			DefineObjCSymbol(DataSymbol, Type::ArrayType(Type::IntegerType(1, false), length),
				fmt::format("nsdata_{:x}_data", i), dataLoc, true);
			DefineObjCSymbol(
				DataSymbol, Type::NamedType(m_data, m_typeNames.nsConstantData), fmt::format("nsdata_{:x}", i), i, true);
		}
		ScopedSymbolQueue::Get().Process();
	}
}

void ObjCProcessor::AddRelocatedPointer(uint64_t location, uint64_t rewrite)
{
	m_relocationPointerRewrites[location] = rewrite;
}
