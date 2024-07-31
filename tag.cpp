#include "tag.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


TagType::TagType(BNTagType* tagType)
{
	m_object = tagType;
}


TagType::TagType(BinaryView* view)
{
	m_object = BNCreateTagType(view->GetObject());
}


TagType::TagType(BinaryView* view, const std::string& name, const std::string& icon, bool visible, TagType::Type type)
{
	m_object = BNCreateTagType(view->GetObject());
	SetName(name);
	SetIcon(icon);
	SetVisible(visible);
	SetType(type);
}


BinaryView* TagType::GetView() const
{
	return new BinaryView(BNTagTypeGetView(m_object));
}


std::string TagType::GetId() const
{
	char* str = BNTagTypeGetId(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


std::string TagType::GetName() const
{
	char* str = BNTagTypeGetName(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


void TagType::SetName(const std::string& name)
{
	BNTagTypeSetName(m_object, name.c_str());
}


std::string TagType::GetIcon() const
{
	return BNTagTypeGetIcon(m_object);
}


void TagType::SetIcon(const std::string& icon)
{
	BNTagTypeSetIcon(m_object, icon.c_str());
}


bool TagType::GetVisible() const
{
	return BNTagTypeGetVisible(m_object);
}


void TagType::SetVisible(bool visible)
{
	BNTagTypeSetVisible(m_object, visible);
}


TagType::Type TagType::GetType() const
{
	return BNTagTypeGetType(m_object);
}


void TagType::SetType(TagType::Type type)
{
	BNTagTypeSetType(m_object, type);
}


Tag::Tag(BNTag* tag)
{
	m_object = tag;
}


Tag::Tag(Ref<TagType> type, const std::string& data)
{
	m_object = BNCreateTag(type->GetObject(), data.c_str());
}


std::string Tag::GetId() const
{
	char* id = BNTagGetId(m_object);
	std::string result = id;
	BNFreeString(id);
	return result;
}


Ref<TagType> Tag::GetType() const
{
	return new TagType(BNTagGetType(m_object));
}


std::string Tag::GetData() const
{
	return BNTagGetData(m_object);
}


void Tag::SetData(const std::string& data)
{
	BNTagSetData(m_object, data.c_str());
}


BNTag** Tag::CreateTagList(const std::vector<Ref<Tag>>& tags, size_t* count)
{
	*count = tags.size();
	BNTag** result = new BNTag*[tags.size()];
	for (size_t i = 0; i < tags.size(); i++)
		result[i] = tags[i]->GetObject();
	return result;
}


std::vector<Ref<Tag>> Tag::ConvertTagList(BNTag** tags, size_t count)
{
	std::vector<Ref<Tag>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(new Tag(BNNewTagReference(tags[i])));
	return result;
}


void Tag::FreeTagList(BNTag** tags, size_t count)
{
	delete[] tags;
	(void)count;
}


std::vector<Ref<Tag>> Tag::ConvertAndFreeTagList(BNTag** tags, size_t count)
{
	auto result = ConvertTagList(tags, count);
	BNFreeTagList(tags, count);
	return result;
}


TagReference::TagReference() {}


TagReference::TagReference(const BNTagReference& ref)
{
	refType = ref.refType;
	autoDefined = ref.autoDefined;
	tag = ref.tag ? new Tag(BNNewTagReference(ref.tag)) : nullptr;
	arch = ref.arch ? new CoreArchitecture(ref.arch) : nullptr;
	func = ref.func ? new Function(BNNewFunctionReference(ref.func)) : nullptr;
	addr = ref.addr;
}


bool TagReference::operator==(const TagReference& other) const
{
	if (refType != other.refType)
		return false;
	if (autoDefined != other.autoDefined)
		return false;
	if (tag != other.tag)
		return false;
	switch (refType)
	{
	case AddressTagReference:
		return func == other.func && arch == other.arch && addr == other.addr;
	case FunctionTagReference:
		return func == other.func;
	case DataTagReference:
		return addr == other.addr;
	default:
		return false;
	}
}


bool TagReference::operator!=(const TagReference& other) const
{
	return !((*this) == other);
}


TagReference::operator BNTagReference() const
{
	BNTagReference ret;
	ret.refType = refType;
	ret.autoDefined = autoDefined;
	ret.tag = tag->GetObject();
	ret.arch = arch ? arch->GetObject() : nullptr;
	ret.func = func ? func->GetObject() : nullptr;
	ret.addr = addr;
	return ret;
}


BNTagReference* TagReference::CreateTagReferenceList(const std::vector<TagReference>& tags, size_t* count)
{
	*count = tags.size();

	BNTagReference* refs = new BNTagReference[*count];

	for (size_t i = 0; i < *count; i++)
	{
		refs[i] = tags[i];
	}

	return refs;
}


std::vector<TagReference> TagReference::ConvertTagReferenceList(BNTagReference* tags, size_t count)
{
	std::vector<TagReference> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.emplace_back(tags[i]);
	}
	return result;
}


void TagReference::FreeTagReferenceList(BNTagReference* tags, size_t count)
{
	delete[] tags;
	(void)count;
}


std::vector<TagReference> TagReference::ConvertAndFreeTagReferenceList(BNTagReference* tags, size_t count)
{
	auto result = ConvertTagReferenceList(tags, count);
	BNFreeTagReferences(tags, count);
	return result;
}

