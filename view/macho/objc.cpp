#include "objc.h"
#include "machoview.h"
#include "inttypes.h"
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"

using namespace BinaryNinja;

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
	char last;

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
				return {}; // seriously malformed type.

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
			nameOrType.type = Type::IntegerType(1, false);
			break;
		case 'i':
			nameOrType.type = Type::IntegerType(4, true);
			break;
		case 'I':
			nameOrType.type = Type::IntegerType(4, false);
			break;
		case 'l':
			nameOrType.type = Type::IntegerType(8, true);
			break;
		case 'L':
			nameOrType.type = Type::IntegerType(8, true);
			break;
		case 'f':
			nameOrType.type = Type::IntegerType(4, true);
			break;
		case 'b':
		case 'B':
			nameOrType.type = Type::BoolType();
			break;
		case 'q':
			qualifiedName = "NSInteger";
			break;
		case 'Q':
			qualifiedName = "NSUInteger";
			break;
		case 'd':
			qualifiedName = "CGFloat";
			break;
		case '*':
			nameOrType.type = Type::PointerType(m_data->GetAddressSize(), Type::IntegerType(1, true));
			break;
		case '@':
			qualifiedName = "id";
			// There can be a type after this, like @"NSString", that overrides this
			// The handler for " will catch it and drop this "id" entry.
			break;
		case ':':
			qualifiedName = "SEL";
			break;
		case '#':
			qualifiedName = "objc_class_t";
			break;
		case '?':
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

	auto process = [=]() {
		NameSpace nameSpace = m_data->GetInternalNameSpace();
		if (type == ExternalSymbol)
		{
			nameSpace = m_data->GetExternalNameSpace();
		}

		std::string shortName = name;
		std::string fullName = name;

		QualifiedName varName;

		return std::pair<Ref<Symbol>, Ref<Type>>(
			new Symbol(type, shortName, fullName, name, addr, GlobalBinding, nameSpace), typeRef);
	};

	if (deferred)
	{
		m_symbolQueue->Append(process, [this, addr=addr](Symbol* symbol, Type* type) {
			// Armv7/Thumb: This will rewrite the symbol's address.
			// e.g. We pass in 0xc001, it will rewrite it to 0xc000 and create the function w/ the "thumb2" arch.
			if (Ref<Symbol> existingSymbol = m_data->GetSymbolByAddress(addr))
				m_data->UndefineAutoSymbol(existingSymbol);
			auto funcSym = m_data->DefineAutoSymbolAndVariableOrFunction(m_data->GetDefaultPlatform(), symbol, type);
			if (funcSym->GetType() == FunctionSymbol)
			{
				uint64_t target = symbol->GetAddress();
				Ref<Platform> targetPlatform = m_data->GetDefaultPlatform()->GetAssociatedPlatformByAddress(target); // rewrites target.
				if (Ref<Function> targetFunction = m_data->GetAnalysisFunction(targetPlatform, target))
				{
					if (!m_isBackedByDatabase)
						targetFunction->SetUserType(type);
				}
			}
		});
		return;
	}

	if (Ref<Symbol> existingSymbol = m_data->GetSymbolByAddress(addr))
		m_data->UndefineAutoSymbol(existingSymbol);
	auto result = process();
	auto sym = m_data->DefineAutoSymbolAndVariableOrFunction(m_data->GetDefaultPlatform(), result.first, result.second);
	if (sym->GetType() == FunctionSymbol)
	{
		uint64_t target = result.first->GetAddress();
		Ref<Platform> targetPlatform = m_data->GetDefaultPlatform()->GetAssociatedPlatformByAddress(target); // rewrites target.
		if (Ref<Function> targetFunction = m_data->GetAnalysisFunction(targetPlatform, target))
		{
			if (!m_isBackedByDatabase)
				targetFunction->SetUserType(result.second);
		}

	}
}

void ObjCProcessor::LoadClasses(BinaryReader* reader, Ref<Section> classPtrSection)
{
	if (!classPtrSection)
		return;
	auto size = classPtrSection->GetEnd() - classPtrSection->GetStart();
	if (size == 0)
		return;
	auto ptrCount = size / m_data->GetAddressSize();

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
		catch (ReadException& ex)
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
		catch (ReadException& ex)
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
			name = reader->ReadCString(500);
		}
		catch (ReadException& ex)
		{
			m_logger->LogWarn(
				"Failed to read class name at 0x%llx. Class has been given the placeholder name \"0x%llx\" ", namePtr,
				classPtr);
			char hexString[9];
			hexString[8] = 0;
			snprintf(hexString, sizeof(hexString), "%llx", classPtr);
			name = "0x" + std::string(hexString);
		}

		cls.name = name;

		DefineObjCSymbol(BNSymbolType::DataSymbol,
			Type::PointerType(m_data->GetAddressSize(), m_data->GetTypeByName(m_typeNames.cls)), "clsPtr_" + name,
			classPointerLocation, true);
		DefineObjCSymbol(BNSymbolType::DataSymbol, m_typeNames.cls, "cls_" + name, classPtr, true);
		DefineObjCSymbol(BNSymbolType::DataSymbol, m_typeNames.classRO, "cls_ro_" + name, classROPtr, true);
		DefineObjCSymbol(BNSymbolType::DataSymbol, Type::ArrayType(Type::IntegerType(1, true), name.size()+1), "clsName_" + name, classRO.name, true);

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
			catch (ReadException& ex)
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
			catch (ReadException& ex)
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
			catch (ReadException& ex)
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
			catch (ReadException& ex)
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
			catch (ReadException& ex)
			{
				m_logger->LogError("Failed to process ivars for class at 0x%llx", clsStruct.data);
			}
		}
		m_classes[classPtr] = cls;
	}
}

void ObjCProcessor::LoadCategories(BinaryReader* reader, Ref<Section> classPtrSection)
{
	if (!classPtrSection)
		return;
	auto size = classPtrSection->GetEnd() - classPtrSection->GetStart();
	if (size == 0)
		return;
	auto ptrSize = m_data->GetAddressSize();
	auto ptrCount = size / m_data->GetAddressSize();

	auto classPtrSectionStart = classPtrSection->GetStart();
	auto classPtrSectionEnd = classPtrSection->GetEnd();

	auto catType = Type::NamedType(m_data, m_typeNames.category);
	auto ptrType = Type::PointerType(m_data->GetDefaultArchitecture(), catType);
	for (size_t i = classPtrSectionStart; i < classPtrSectionEnd; i += ptrSize)
	{
		Class category;
		category_t cat;

		reader->Seek(i);
		m_data->DefineDataVariable(i, ptrType);
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
		catch (ReadException& ex)
		{
			m_logger->LogError("Failed to read category pointed to by 0x%llx", i);
			continue;
		}
		m_data->DefineDataVariable(catLocation, catType);

		std::string categoryAdditionsName;
		std::string categoryBaseClassName;

		if (const auto& it = m_classes.find(cat.cls); it != m_classes.end())
		{
			categoryBaseClassName = it->second.name;
			category.associatedName = it->second.associatedName;
		}
		else if (auto symbol = m_data->GetSymbolByAddress(catLocation + m_data->GetAddressSize()))
		{
			if (symbol->GetType() == ImportedDataSymbol || symbol->GetType() == ImportAddressSymbol)
			{
				const auto& symbolName = symbol->GetFullName();
				if (symbolName.size() > 14 && symbolName.rfind("_OBJC_CLASS_$_", 0) == 0)
					categoryBaseClassName = symbolName.substr(14, symbolName.size() - 14);
			}
		}
		if (categoryBaseClassName.empty())
		{
			m_logger->LogError(
				"Failed to determine base classname for category at 0x%llx. Using base address as stand-in classname",
				catLocation);
			categoryBaseClassName = std::to_string(catLocation);
		}
		try
		{
			reader->Seek(cat.name);
			categoryAdditionsName = reader->ReadCString();
		}
		catch (ReadException& ex)
		{
			m_logger->LogError(
				"Failed to read category name for category at 0x%llx. Using base address as stand-in category name",
				catLocation);
			categoryAdditionsName = std::to_string(catLocation);
		}
		category.name = categoryBaseClassName + " (" + categoryAdditionsName + ")";

		if (cat.instanceMethods)
		{
			try
			{
				ReadMethodList(reader, category.instanceClass, category.name, cat.instanceMethods);
			}
			catch (ReadException& ex)
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
			catch (ReadException& ex)
			{
				m_logger->LogError(
					"Failed to read the class method list for category pointed to by 0x%llx", catLocation);
			}
		}
		m_categories[catLocation] = category;
	}
}

void ObjCProcessor::ReadMethodList(BinaryReader* reader, ClassBase& cls, std::string name, view_ptr_t start)
{
	reader->Seek(start);
	method_list_t head;
	head.entsizeAndFlags = reader->Read32();
	head.count = reader->Read32();
	uint64_t pointerSize = m_data->GetAddressSize();
	bool relativeOffsets = (head.entsizeAndFlags & 0xFFFF0000) & 0x80000000;
	bool directSelectors = (head.entsizeAndFlags & 0xFFFF0000) & 0x40000000;
	auto methodSize = relativeOffsets ? 12 : pointerSize * 3;
	DefineObjCSymbol(DataSymbol, m_typeNames.methodList, "method_list_" + name, start, true);

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
				meth.name = cursor + static_cast<int32_t>(reader->Read32());
				meth.types = cursor + 4 + static_cast<int32_t>(reader->Read32());
				meth.imp = cursor + 8 + static_cast<int32_t>(reader->Read32());
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
					method.name = reader->ReadCString(selRef);
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
		}
		catch (ReadException& ex)
		{
			m_logger->LogError(
				"Failed to process a method at offset 0x%llx", start + sizeof(method_list_t) + (i * methodSize));
		}
	}
}

void ObjCProcessor::ReadIvarList(BinaryReader* reader, ClassBase& cls, std::string name, view_ptr_t start)
{
	reader->Seek(start);
	ivar_list_t head;
	head.entsizeAndFlags = reader->Read32();
	head.count = reader->Read32();
	auto addressSize = m_data->GetAddressSize();
	DefineObjCSymbol(DataSymbol, m_typeNames.ivarList, "ivar_list_" + name, start, true);
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

			reader->Seek(ivarStruct.offset);
			ivar.offset = reader->Read32();
			reader->Seek(ivarStruct.name);
			ivar.name = reader->ReadCString();
			reader->Seek(ivarStruct.type);
			ivar.type = reader->ReadCString();

			DefineObjCSymbol(DataSymbol, m_typeNames.ivar, "ivar_" + ivar.name, cursor, true);

			cls.ivarList[cursor] = ivar;
		}
		catch (ReadException& ex)
		{
			m_logger->LogError("Failed to process an ivar at offset 0x%llx",
				start + (sizeof(ivar_list_t)) + (i * ((addressSize * 3) + 8)));
		}
	}
}

bool ObjCProcessor::ViewHasObjCMetadata(BinaryNinja::BinaryView* data)
{
	return (data->GetSectionByName("__objc_classlist") || data->GetSectionByName("__objc_catlist")
		|| data->GetSectionByName("__objc_protolist"));
}


std::pair<QualifiedName, Ref<Type>> finalizeStructureBuilder(
	Ref<BinaryView> m_data, StructureBuilder sb, std::string name)
{
	auto classTypeStruct = sb.Finalize();

	QualifiedName classTypeName(name);
	auto classTypeId = Type::GenerateAutoTypeId("objc", classTypeName);
	auto classType = Type::StructureType(classTypeStruct);
	auto classQualName = m_data->DefineType(classTypeId, classTypeName, classType);

	return {classQualName, classType};
}

std::pair<QualifiedName, Ref<Type>> finalizeEnumerationBuilder(
	Ref<BinaryView> m_data, EnumerationBuilder eb, uint64_t size, QualifiedName name)
{
	auto enumTypeStruct = eb.Finalize();

	auto enumTypeId = Type::GenerateAutoTypeId("objc", name);
	auto enumType = Type::EnumerationType(enumTypeStruct, size);
	auto enumQualName = m_data->DefineType(enumTypeId, name, enumType);

	return {enumQualName, enumType};
}

inline QualifiedName defineTypedef(Ref<BinaryView> m_data, const QualifiedName name, Ref<Type> type)
{
	auto typeID = Type::GenerateAutoTypeId("objc", name);
	m_data->DefineType(typeID, name, type);
	return m_data->GetTypeNameById(typeID);
}

void ObjCProcessor::GenerateClassTypes()
{
	for (auto& [_, cls] : m_classes)
	{
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
		QualifiedName classTypeName = cls.name;
		std::string classTypeId = Type::GenerateAutoTypeId("objc", classTypeName);
		Ref<Type> classType = Type::StructureType(classTypeStruct);
		QualifiedName classQualName = m_data->DefineType(classTypeId, classTypeName, classType);
		cls.associatedName = classTypeName;
	}
}

bool ObjCProcessor::ApplyMethodType(Class& cls, Method& method, bool isInstanceMethod)
{
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
			Type::NamedType(m_data, {"id"}) :
			Type::PointerType(m_data->GetAddressSize(), Type::NamedType(m_data, cls.associatedName)),
		true, BinaryNinja::Variable()});

	params.push_back({"sel", Type::NamedType(m_data, {"SEL"}), true, BinaryNinja::Variable()});

	for (size_t i = 3; i < typeTokens.size(); i++)
	{
		std::string suffix;

		params.push_back({selectorTokens.size() > i - 3 ? selectorTokens[i - 3] : "arg",
			typeForQualifiedNameOrType(typeTokens[i]), true, BinaryNinja::Variable()});
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

void ObjCProcessor::PostProcessObjCSections(BinaryReader* reader)
{
	auto ptrSize = m_data->GetAddressSize();
	if (auto imageInfo = m_data->GetSectionByName("__objc_imageinfo"))
	{
		auto start = imageInfo->GetStart();
		auto type = Type::NamedType(m_data, m_typeNames.imageInfo);
		m_data->DefineDataVariable(start, type);
	}
	if (auto selrefs = m_data->GetSectionByName("__objc_selrefs"))
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
				DefineObjCSymbol(DataSymbol, Type::ArrayType(Type::IntegerType(1, true), sel.size() + 1),
					"sel_" + sel, selLoc, true);
			}
			DefineObjCSymbol(DataSymbol, type, "selRef_" + sel, i, true);
		}
	}
	if (auto superRefs = m_data->GetSectionByName("__objc_classrefs"))
	{
		auto start = superRefs->GetStart();
		auto end = superRefs->GetEnd();
		auto type = Type::PointerType(ptrSize, Type::NamedType(m_data, m_typeNames.cls));
		for (view_ptr_t i = start; i < end; i += ptrSize)
		{
			m_data->DefineDataVariable(i, type);
		}
	}
	if (auto superRefs = m_data->GetSectionByName("__objc_superrefs"))
	{
		auto start = superRefs->GetStart();
		auto end = superRefs->GetEnd();
		auto type = Type::PointerType(ptrSize, Type::NamedType(m_data, m_typeNames.cls));
		for (view_ptr_t i = start; i < end; i += ptrSize)
		{
			m_data->DefineDataVariable(i, type);
		}
	}
	if (auto cfstrings = m_data->GetSectionByName("__cfstring"))
	{
		auto start = cfstrings->GetStart();
		auto end = cfstrings->GetEnd();
		auto type = Type::NamedType(m_data, m_typeNames.cfString);
		auto typeWidth = type->GetWidth();
		for (view_ptr_t i = start; i < end; i += typeWidth)
		{
			reader->Seek(i + ptrSize);
			uint64_t flags = reader->ReadPointer();
			auto strLoc = ReadPointerAccountingForRelocations(reader);
			auto size = reader->ReadPointer();
			std::string str;
			if (flags & 0b10000) // UTF16
			{
				m_data->DefineDataVariable(i, Type::NamedType(m_data, m_typeNames.cfStringUTF16));
				auto data = m_data->ReadBuffer(strLoc, size * 2);

				str = "";
				for (uint64_t bufferOff = 0; bufferOff < size * 2; bufferOff += 2)
				{
					uint8_t* rawData = static_cast<uint8_t*>(data.GetData());
					uint8_t* offsetAddress = rawData + bufferOff;
					uint16_t c = *reinterpret_cast<uint16_t*>(offsetAddress);
					if (c == 0x20)
						str.push_back('_');
					else if (c < 0x80)
						str.push_back(c);
					else
						str.push_back('?');
				}
				DefineObjCSymbol(DataSymbol, Type::ArrayType(Type::WideCharType(2), size + 1),
					"ustr_" + str, strLoc, true);
				DefineObjCSymbol(DataSymbol, Type::NamedType(m_data, m_typeNames.cfStringUTF16), "cfstr_" + str, i, true);
			}
			else // UTF8 / ASCII
			{
				reader->Seek(strLoc);
				str = reader->ReadCString(size + 1);
				for (auto& c : str)
				{
					if (c == ' ')
						c = '_';
				}
				DefineObjCSymbol(DataSymbol, Type::ArrayType(Type::IntegerType(1, true), str.size() + 1),
					"cstr_" + str, strLoc, true);
				DefineObjCSymbol(DataSymbol, Type::NamedType(m_data, m_typeNames.cfString), "cfstr_" + str, i, true);
			}
		}
	}
}

uint64_t ObjCProcessor::ReadPointerAccountingForRelocations(BinaryReader* reader)
{
	if (auto it = m_relocationPointerRewrites.find(reader->GetOffset()); it != m_relocationPointerRewrites.end())
	{
		reader->SeekRelative(m_data->GetAddressSize());
		return it->second;
	}
	return reader->ReadPointer();
}


ObjCProcessor::ObjCProcessor(BinaryNinja::BinaryView* data, bool isBackedByDatabase) : m_isBackedByDatabase(isBackedByDatabase), m_data(data)
{
	m_logger = m_data->CreateLogger("macho.objc");
	m_symbolQueue = new SymbolQueue();
}

void ObjCProcessor::ProcessObjCData()
{
	auto addrSize = m_data->GetAddressSize();

	m_typeNames.relativePtr = defineTypedef(m_data, {"rptr_t"}, Type::IntegerType(4, true));
	auto rptr_t = Type::NamedType(m_data, m_typeNames.relativePtr);

	m_typeNames.id = defineTypedef(m_data, {"id"}, Type::PointerType(addrSize, Type::VoidType()));
	m_typeNames.sel = defineTypedef(m_data, {"SEL"}, Type::PointerType(addrSize, Type::IntegerType(1, false)));

	m_typeNames.BOOL = defineTypedef(m_data, {"BOOL"}, Type::IntegerType(1, false));
	m_typeNames.nsInteger = defineTypedef(m_data, {"NSInteger"}, Type::IntegerType(addrSize, true));
	m_typeNames.nsuInteger = defineTypedef(m_data, {"NSUInteger"}, Type::IntegerType(addrSize, false));
	m_typeNames.cgFloat = defineTypedef(m_data, {"CGFloat"}, Type::FloatType(addrSize));

	// https://github.com/apple/llvm-project/blob/next/clang/lib/CodeGen/CodeGenModule.cpp#L6129
	// See also ASTContext.cpp ctrl+f __NSConstantString_tag

	// The place these flags are used is unclear, along with any clear flag definitions, but they are useful for introspection
	EnumerationBuilder __cfStringFlagBuilder;
	__cfStringFlagBuilder.AddMemberWithValue("SwiftABI", 0b1);
	__cfStringFlagBuilder.AddMemberWithValue("Swift4_1", 0b100);
	// LLVM also sets 0x7c0 (0b11111000000) on both UTF8 and UTF16 strings however it is unclear what this denotes.
	__cfStringFlagBuilder.AddMemberWithValue("UTF8", 0b1000);
	__cfStringFlagBuilder.AddMemberWithValue("UTF16", 0b10000);
	auto type = finalizeEnumerationBuilder(m_data, __cfStringFlagBuilder, addrSize, {"CFStringFlag"});
	m_typeNames.cfStringFlag = type.first;

	StructureBuilder __cfStringStructBuilder;
	__cfStringStructBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "isa");
	__cfStringStructBuilder.AddMember(Type::NamedType(m_data, m_typeNames.cfStringFlag), "flags");
	__cfStringStructBuilder.AddMember(Type::PointerType(addrSize, Type::IntegerType(1, true)), "data");
	__cfStringStructBuilder.AddMember(Type::IntegerType(addrSize, false), "length");
	type = finalizeStructureBuilder(m_data, __cfStringStructBuilder, "__NSConstantString");
	m_typeNames.cfString = type.first;

	StructureBuilder __cfStringUTF16StructBuilder;
	__cfStringUTF16StructBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "isa");
	__cfStringUTF16StructBuilder.AddMember(Type::NamedType(m_data, m_typeNames.cfStringFlag), "flags");
	__cfStringUTF16StructBuilder.AddMember(Type::PointerType(addrSize, Type::IntegerType(2, true)), "data");
	__cfStringUTF16StructBuilder.AddMember(Type::IntegerType(addrSize, false), "length");
	type = finalizeStructureBuilder(m_data, __cfStringUTF16StructBuilder, "__NSConstantString_UTF16");
	m_typeNames.cfStringUTF16 = type.first;

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
	auto swiftVersionType = finalizeEnumerationBuilder(m_data, swiftVersionBuilder, 4, {"objc_image_info_swift_version"});
	m_typeNames.imageInfoSwiftVersion = swiftVersionType.first;

	StructureBuilder imageInfoBuilder;
	imageInfoBuilder.AddMember(Type::IntegerType(4, false), "version");
	imageInfoBuilder.AddMember(Type::NamedType(m_data, m_typeNames.imageInfoFlags), "flags");
	auto imageInfoType = finalizeStructureBuilder(m_data, imageInfoBuilder, "objc_image_info_t");
	m_typeNames.imageInfo = imageInfoType.first;

	StructureBuilder methodEntry;
	methodEntry.AddMember(rptr_t, "name");
	methodEntry.AddMember(rptr_t, "types");
	methodEntry.AddMember(rptr_t, "imp");
	type = finalizeStructureBuilder(m_data, methodEntry, "objc_method_entry_t");
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

	StructureBuilder classROBuilder;
	classROBuilder.AddMember(Type::IntegerType(4, false), "flags");
	classROBuilder.AddMember(Type::IntegerType(4, false), "start");
	classROBuilder.AddMember(Type::IntegerType(4, false), "size");
	if (addrSize == 8)
		classROBuilder.AddMember(Type::IntegerType(4, false), "reserved");
	classROBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "ivar_layout");
	classROBuilder.AddMember(Type::PointerType(addrSize, Type::IntegerType(1, true)), "name");
	classROBuilder.AddMember(Type::PointerType(addrSize, Type::NamedType(m_data, m_typeNames.methodList)), "methods");
	classROBuilder.AddMember(Type::PointerType(addrSize, Type::VoidType()), "protocols");
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

	auto classTypeStruct = classBuilder.Finalize();
	auto classType = Type::StructureType(classTypeStruct);
	auto classQualName = m_data->DefineType(classTypeId, classTypeName, classType);

	m_typeNames.cls = classQualName;

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


	auto reader = new BinaryReader(m_data);
	m_data->BeginBulkModifySymbols();
	if (auto classList = m_data->GetSectionByName("__objc_classlist"))
		LoadClasses(reader, classList);
	if (auto nonLazyClassList = m_data->GetSectionByName("__objc_nlclslist"))
		LoadClasses(reader, nonLazyClassList);  // See: https://stackoverflow.com/a/15318325

	GenerateClassTypes();
	for (auto& [_, cls] : m_classes)
		ApplyMethodTypes(cls);

	if (auto catList = m_data->GetSectionByName("__objc_catlist"))  // Do this after loading class type data.
		LoadCategories(reader, catList);
	for (auto& [_, cat] : m_categories)
		ApplyMethodTypes(cat);

	PostProcessObjCSections(reader);

	m_symbolQueue->Process();
	m_data->EndBulkModifySymbols();
	delete m_symbolQueue;

	auto meta = SerializeMetadata();
	m_data->StoreMetadata("Objective-C", meta, true);

	m_relocationPointerRewrites.clear();
}

void ObjCProcessor::AddRelocatedPointer(uint64_t location, uint64_t rewrite)
{
	m_relocationPointerRewrites[location] = rewrite;
}
