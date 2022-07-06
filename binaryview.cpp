// Copyright (c) 2015-2022 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include <algorithm>
#include <iterator>
#include <memory>
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


void BinaryDataNotification::DataWrittenCallback(void* ctxt, BNBinaryView* object, uint64_t offset, size_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnBinaryDataWritten(view, offset, len);
}


void BinaryDataNotification::DataInsertedCallback(void* ctxt, BNBinaryView* object, uint64_t offset, size_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnBinaryDataInserted(view, offset, len);
}


void BinaryDataNotification::DataRemovedCallback(void* ctxt, BNBinaryView* object, uint64_t offset, uint64_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnBinaryDataRemoved(view, offset, len);
}


void BinaryDataNotification::FunctionAddedCallback(void* ctxt, BNBinaryView* object, BNFunction* func)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	notify->OnAnalysisFunctionAdded(view, funcObj);
}


void BinaryDataNotification::FunctionRemovedCallback(void* ctxt, BNBinaryView* object, BNFunction* func)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	notify->OnAnalysisFunctionRemoved(view, funcObj);
}


void BinaryDataNotification::FunctionUpdatedCallback(void* ctxt, BNBinaryView* object, BNFunction* func)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	notify->OnAnalysisFunctionUpdated(view, funcObj);
}


void BinaryDataNotification::FunctionUpdateRequestedCallback(void* ctxt, BNBinaryView* object, BNFunction* func)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<Function> funcObj = new Function(BNNewFunctionReference(func));
	notify->OnAnalysisFunctionUpdateRequested(view, funcObj);
}


void BinaryDataNotification::DataVariableAddedCallback(void* ctxt, BNBinaryView* object, BNDataVariable* var)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	DataVariable varObj(var->address,
	    Confidence<Ref<Type>>(new Type(BNNewTypeReference(var->type)), var->typeConfidence), var->autoDiscovered);
	notify->OnDataVariableAdded(view, varObj);
}


void BinaryDataNotification::DataVariableRemovedCallback(void* ctxt, BNBinaryView* object, BNDataVariable* var)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	DataVariable varObj(var->address,
	    Confidence<Ref<Type>>(new Type(BNNewTypeReference(var->type)), var->typeConfidence), var->autoDiscovered);
	notify->OnDataVariableRemoved(view, varObj);
}


void BinaryDataNotification::DataVariableUpdatedCallback(void* ctxt, BNBinaryView* object, BNDataVariable* var)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	DataVariable varObj(var->address,
	    Confidence<Ref<Type>>(new Type(BNNewTypeReference(var->type)), var->typeConfidence), var->autoDiscovered);
	notify->OnDataVariableUpdated(view, varObj);
}


void BinaryDataNotification::DataMetadataUpdatedCallback(void* ctxt, BNBinaryView* object, uint64_t offset)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnDataMetadataUpdated(view, offset);
}


void BinaryDataNotification::TagTypeUpdatedCallback(void* ctxt, BNBinaryView* object, BNTagType* tagType)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<TagType> tagTypeRef = new TagType(BNNewTagTypeReference(tagType));
	notify->OnTagTypeUpdated(view, tagTypeRef);
}


void BinaryDataNotification::TagAddedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnTagAdded(view, TagReference(*tagRef));
}


void BinaryDataNotification::TagUpdatedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnTagUpdated(view, TagReference(*tagRef));
}


void BinaryDataNotification::TagRemovedCallback(void* ctxt, BNBinaryView* object, BNTagReference* tagRef)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnTagRemoved(view, TagReference(*tagRef));
}


void BinaryDataNotification::SymbolAddedCallback(void* ctxt, BNBinaryView* object, BNSymbol* symobj)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<Symbol> sym = new Symbol(BNNewSymbolReference(symobj));
	notify->OnSymbolAdded(view, sym);
}


void BinaryDataNotification::SymbolUpdatedCallback(void* ctxt, BNBinaryView* object, BNSymbol* symobj)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<Symbol> sym = new Symbol(BNNewSymbolReference(symobj));
	notify->OnSymbolUpdated(view, sym);
}


void BinaryDataNotification::SymbolRemovedCallback(void* ctxt, BNBinaryView* object, BNSymbol* symobj)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	Ref<Symbol> sym = new Symbol(BNNewSymbolReference(symobj));
	notify->OnSymbolRemoved(view, sym);
}


void BinaryDataNotification::StringFoundCallback(
    void* ctxt, BNBinaryView* object, BNStringType type, uint64_t offset, size_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnStringFound(view, type, offset, len);
}


void BinaryDataNotification::StringRemovedCallback(
    void* ctxt, BNBinaryView* object, BNStringType type, uint64_t offset, size_t len)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(object));
	notify->OnStringRemoved(view, type, offset, len);
}


void BinaryDataNotification::TypeDefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	notify->OnTypeDefined(view, QualifiedName::FromAPIObject(name), typeObj);
}


void BinaryDataNotification::TypeUndefinedCallback(void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	notify->OnTypeUndefined(view, QualifiedName::FromAPIObject(name), typeObj);
}


void BinaryDataNotification::TypeReferenceChangedCallback(
    void* ctxt, BNBinaryView* data, BNQualifiedName* name, BNType* type)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Type> typeObj = new Type(BNNewTypeReference(type));
	notify->OnTypeReferenceChanged(view, QualifiedName::FromAPIObject(name), typeObj);
}


void BinaryDataNotification::TypeFieldReferenceChangedCallback(
    void* ctxt, BNBinaryView* data, BNQualifiedName* name, uint64_t offset)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	notify->OnTypeFieldReferenceChanged(view, QualifiedName::FromAPIObject(name), offset);
}


void BinaryDataNotification::SegmentAddedCallback(void* ctxt, BNBinaryView* data, BNSegment* segment)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Segment> segmentObj = new Segment(BNNewSegmentReference(segment));

	notify->OnSegmentAdded(view, segmentObj);
}


void BinaryDataNotification::SegmentUpdatedCallback(void* ctxt, BNBinaryView* data, BNSegment* segment)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Segment> segmentObj = new Segment(BNNewSegmentReference(segment));

	notify->OnSegmentUpdated(view, segmentObj);
}


void BinaryDataNotification::SegmentRemovedCallback(void* ctxt, BNBinaryView* data, BNSegment* segment)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Segment> segmentObj = new Segment(BNNewSegmentReference(segment));

	notify->OnSegmentRemoved(view, segmentObj);
}


void BinaryDataNotification::SectionAddedCallback(void* ctxt, BNBinaryView* data, BNSection* section)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Section> sectionObj = new Section(BNNewSectionReference(section));

	notify->OnSectionAdded(view, sectionObj);
}


void BinaryDataNotification::SectionUpdatedCallback(void* ctxt, BNBinaryView* data, BNSection* section)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Section> sectionObj = new Section(BNNewSectionReference(section));

	notify->OnSectionUpdated(view, sectionObj);
}


void BinaryDataNotification::SectionRemovedCallback(void* ctxt, BNBinaryView* data, BNSection* section)
{
	BinaryDataNotification* notify = (BinaryDataNotification*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	Ref<Section> sectionObj = new Section(BNNewSectionReference(section));

	notify->OnSectionRemoved(view, sectionObj);
}


BinaryDataNotification::BinaryDataNotification()
{
	m_callbacks.context = this;
	m_callbacks.dataWritten = DataWrittenCallback;
	m_callbacks.dataInserted = DataInsertedCallback;
	m_callbacks.dataRemoved = DataRemovedCallback;
	m_callbacks.functionAdded = FunctionAddedCallback;
	m_callbacks.functionRemoved = FunctionRemovedCallback;
	m_callbacks.functionUpdated = FunctionUpdatedCallback;
	m_callbacks.functionUpdateRequested = FunctionUpdateRequestedCallback;
	m_callbacks.dataVariableAdded = DataVariableAddedCallback;
	m_callbacks.dataVariableRemoved = DataVariableRemovedCallback;
	m_callbacks.dataVariableUpdated = DataVariableUpdatedCallback;
	m_callbacks.dataMetadataUpdated = DataMetadataUpdatedCallback;
	m_callbacks.tagTypeUpdated = TagTypeUpdatedCallback;
	m_callbacks.tagAdded = TagAddedCallback;
	m_callbacks.tagUpdated = TagUpdatedCallback;
	m_callbacks.tagRemoved = TagRemovedCallback;
	m_callbacks.symbolAdded = SymbolAddedCallback;
	m_callbacks.symbolUpdated = SymbolUpdatedCallback;
	m_callbacks.symbolRemoved = SymbolRemovedCallback;
	m_callbacks.stringFound = StringFoundCallback;
	m_callbacks.stringRemoved = StringRemovedCallback;
	m_callbacks.typeDefined = TypeDefinedCallback;
	m_callbacks.typeUndefined = TypeUndefinedCallback;
	m_callbacks.typeReferenceChanged = TypeReferenceChangedCallback;
	m_callbacks.typeFieldReferenceChanged = TypeFieldReferenceChangedCallback;
	m_callbacks.segmentAdded = SegmentAddedCallback;
	m_callbacks.segmentUpdated = SegmentUpdatedCallback;
	m_callbacks.segmentRemoved = SegmentRemovedCallback;
	m_callbacks.sectionAdded = SectionAddedCallback;
	m_callbacks.sectionUpdated = SectionUpdatedCallback;
	m_callbacks.sectionRemoved = SectionRemovedCallback;
}


Symbol::Symbol(BNSymbolType type, const string& shortName, const string& fullName, const string& rawName, uint64_t addr,
    BNSymbolBinding binding, const NameSpace& nameSpace, uint64_t ordinal)
{
	BNNameSpace ns = nameSpace.GetAPIObject();
	m_object = BNCreateSymbol(type, shortName.c_str(), fullName.c_str(), rawName.c_str(), addr, binding, &ns, ordinal);
	NameSpace::FreeAPIObject(&ns);
}


Symbol::Symbol(BNSymbolType type, const std::string& name, uint64_t addr, BNSymbolBinding binding,
    const NameSpace& nameSpace, uint64_t ordinal)
{
	BNNameSpace ns = nameSpace.GetAPIObject();
	m_object = BNCreateSymbol(type, name.c_str(), name.c_str(), name.c_str(), addr, binding, &ns, ordinal);
	NameSpace::FreeAPIObject(&ns);
}


Symbol::Symbol(BNSymbol* sym)
{
	m_object = sym;
}


BNSymbolType Symbol::GetType() const
{
	return BNGetSymbolType(m_object);
}


BNSymbolBinding Symbol::GetBinding() const
{
	return BNGetSymbolBinding(m_object);
}


NameSpace Symbol::GetNameSpace() const
{
	BNNameSpace name = BNGetSymbolNameSpace(m_object);
	NameSpace result = NameSpace::FromAPIObject(&name);
	BNFreeNameSpace(&name);
	return result;
}


string Symbol::GetShortName() const
{
	char* name = BNGetSymbolShortName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


string Symbol::GetFullName() const
{
	char* name = BNGetSymbolFullName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


string Symbol::GetRawName() const
{
	char* name = BNGetSymbolRawName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


uint64_t Symbol::GetAddress() const
{
	return BNGetSymbolAddress(m_object);
}


uint64_t Symbol::GetOrdinal() const
{
	return BNGetSymbolOrdinal(m_object);
}


bool Symbol::IsAutoDefined() const
{
	return BNIsSymbolAutoDefined(m_object);
}


Ref<Symbol> Symbol::ImportedFunctionFromImportAddressSymbol(Symbol* sym, uint64_t addr)
{
	return new Symbol(BNImportedFunctionFromImportAddressSymbol(sym->GetObject(), addr));
}


AnalysisCompletionEvent::AnalysisCompletionEvent(BinaryView* view, const std::function<void()>& callback) :
    m_callback(callback)
{
	m_object = BNAddAnalysisCompletionEvent(view->GetObject(), this, CompletionCallback);
}


void AnalysisCompletionEvent::CompletionCallback(void* ctxt)
{
	AnalysisCompletionEvent* event = (AnalysisCompletionEvent*)ctxt;

	unique_lock<recursive_mutex> lock(event->m_mutex);
	event->m_callback();
	event->m_callback = []() {
	};
}


void AnalysisCompletionEvent::Cancel()
{
	unique_lock<recursive_mutex> lock(m_mutex);
	m_callback = []() {
	};
	// This allows the API side to free the BinaryNinja::AnalysisCompletionEvent object
	BNCancelAnalysisCompletionEvent(m_object);
}


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


std::vector<TagReference> TagReference::ConvertAndFreeTagReferenceList(BNTagReference* tags, size_t count)
{
	auto result = ConvertTagReferenceList(tags, count);
	BNFreeTagReferences(tags, count);
	return result;
}


Segment::Segment(BNSegment* seg)
{
	m_object = seg;
}


vector<pair<uint64_t, uint64_t>> Segment::GetRelocationRanges() const
{
	size_t count = 0;
	BNRange* ranges = BNSegmentGetRelocationRanges(m_object, &count);
	vector<pair<uint64_t, uint64_t>> result(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back({ranges[i].start, ranges[i].end});
	}
	BNFreeRelocationRanges(ranges);
	return result;
}


vector<pair<uint64_t, uint64_t>> Segment::GetRelocationRangesAtAddress(uint64_t addr) const
{
	size_t count = 0;
	BNRange* ranges = BNSegmentGetRelocationRangesAtAddress(m_object, addr, &count);
	vector<pair<uint64_t, uint64_t>> result(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back({ranges[i].start, ranges[i].end});
	}
	BNFreeRelocationRanges(ranges);
	return result;
}


uint64_t Segment::GetRelocationsCount() const
{
	return BNSegmentGetRelocationsCount(m_object);
}


uint64_t Segment::GetStart() const
{
	return BNSegmentGetStart(m_object);
}


uint64_t Segment::GetLength() const
{
	return BNSegmentGetLength(m_object);
}


uint64_t Segment::GetEnd() const
{
	return BNSegmentGetEnd(m_object);
}


uint64_t Segment::GetDataEnd() const
{
	return BNSegmentGetDataEnd(m_object);
}


uint64_t Segment::GetDataOffset() const
{
	return BNSegmentGetDataOffset(m_object);
}


uint64_t Segment::GetDataLength() const
{
	return BNSegmentGetDataLength(m_object);
}


uint32_t Segment::GetFlags() const
{
	return BNSegmentGetFlags(m_object);
}


bool Segment::IsAutoDefined() const
{
	return BNSegmentIsAutoDefined(m_object);
}


void Segment::SetLength(uint64_t length)
{
	BNSegmentSetLength(m_object, length);
}


void Segment::SetDataOffset(uint64_t dataOffset)
{
	BNSegmentSetDataOffset(m_object, dataOffset);
}


void Segment::SetDataLength(uint64_t dataLength)
{
	BNSegmentSetDataLength(m_object, dataLength);
}


void Segment::SetFlags(uint32_t flags)
{
	BNSegmentSetFlags(m_object, flags);
}


Section::Section(BNSection* sec)
{
	m_object = sec;
}


std::string Section::GetName() const
{
	char* str = BNSectionGetName(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


std::string Section::GetType() const
{
	char* str = BNSectionGetType(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


uint64_t Section::GetStart() const
{
	return BNSectionGetStart(m_object);
}


uint64_t Section::GetLength() const
{
	return BNSectionGetLength(m_object);
}


uint64_t Section::GetInfoData() const
{
	return BNSectionGetInfoData(m_object);
}


uint64_t Section::GetAlignment() const
{
	return BNSectionGetAlign(m_object);
}


uint64_t Section::GetEntrySize() const
{
	return BNSectionGetEntrySize(m_object);
}


std::string Section::GetLinkedSection() const
{
	return BNSectionGetLinkedSection(m_object);
}


std::string Section::GetInfoSection() const
{
	return BNSectionGetInfoSection(m_object);
}


BNSectionSemantics Section::GetSemantics() const
{
	return BNSectionGetSemantics(m_object);
}


bool Section::AutoDefined() const
{
	return BNSectionIsAutoDefined(m_object);
}


BinaryView::BinaryView(const std::string& typeName, FileMetadata* file, BinaryView* parentView)
{
	BNCustomBinaryView view;
	view.context = this;
	view.init = InitCallback;
	view.freeObject = FreeCallback;
	view.externalRefTaken = nullptr;
	view.externalRefReleased = nullptr;
	view.read = ReadCallback;
	view.write = WriteCallback;
	view.insert = InsertCallback;
	view.remove = RemoveCallback;
	view.getModification = GetModificationCallback;
	view.isValidOffset = IsValidOffsetCallback;
	view.isOffsetReadable = IsOffsetReadableCallback;
	view.isOffsetWritable = IsOffsetWritableCallback;
	view.isOffsetExecutable = IsOffsetExecutableCallback;
	view.isOffsetBackedByFile = IsOffsetBackedByFileCallback;
	view.getNextValidOffset = GetNextValidOffsetCallback;
	view.getStart = GetStartCallback;
	view.getLength = GetLengthCallback;
	view.getEntryPoint = GetEntryPointCallback;
	view.isExecutable = IsExecutableCallback;
	view.getDefaultEndianness = GetDefaultEndiannessCallback;
	view.isRelocatable = IsRelocatableCallback;
	view.getAddressSize = GetAddressSizeCallback;
	view.save = SaveCallback;
	m_file = file;
	AddRefForRegistration();
	m_object = BNCreateCustomBinaryView(
	    typeName.c_str(), m_file->GetObject(), parentView ? parentView->GetObject() : nullptr, &view);
}


BinaryView::BinaryView(BNBinaryView* view)
{
	m_object = view;
	m_file = new FileMetadata(BNGetFileForView(m_object));
}


bool BinaryView::InitCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->Init();
}


void BinaryView::FreeCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	view->ReleaseForRegistration();
}


size_t BinaryView::ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformRead(dest, offset, len);
}


size_t BinaryView::WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformWrite(offset, src, len);
}


size_t BinaryView::InsertCallback(void* ctxt, uint64_t offset, const void* src, size_t len)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformInsert(offset, src, len);
}


size_t BinaryView::RemoveCallback(void* ctxt, uint64_t offset, uint64_t len)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformRemove(offset, len);
}


BNModificationStatus BinaryView::GetModificationCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetModification(offset);
}


bool BinaryView::IsValidOffsetCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsValidOffset(offset);
}


bool BinaryView::IsOffsetReadableCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsOffsetReadable(offset);
}


bool BinaryView::IsOffsetWritableCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsOffsetWritable(offset);
}


bool BinaryView::IsOffsetExecutableCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsOffsetExecutable(offset);
}


bool BinaryView::IsOffsetBackedByFileCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsOffsetBackedByFile(offset);
}


uint64_t BinaryView::GetNextValidOffsetCallback(void* ctxt, uint64_t offset)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetNextValidOffset(offset);
}


uint64_t BinaryView::GetStartCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetStart();
}


uint64_t BinaryView::GetLengthCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetLength();
}


uint64_t BinaryView::GetEntryPointCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetEntryPoint();
}


bool BinaryView::IsExecutableCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsExecutable();
}


BNEndianness BinaryView::GetDefaultEndiannessCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetDefaultEndianness();
}


bool BinaryView::IsRelocatableCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformIsRelocatable();
}


size_t BinaryView::GetAddressSizeCallback(void* ctxt)
{
	BinaryView* view = (BinaryView*)ctxt;
	return view->PerformGetAddressSize();
}


bool BinaryView::SaveCallback(void* ctxt, BNFileAccessor* file)
{
	BinaryView* view = (BinaryView*)ctxt;
	CoreFileAccessor accessor(file);
	return view->PerformSave(&accessor);
}


bool BinaryView::PerformIsValidOffset(uint64_t offset)
{
	uint8_t val;
	return PerformRead(&val, offset, 1) == 1;
}


bool BinaryView::PerformIsOffsetReadable(uint64_t offset)
{
	return PerformIsValidOffset(offset);
}


bool BinaryView::PerformIsOffsetWritable(uint64_t offset)
{
	return PerformIsValidOffset(offset);
}


bool BinaryView::PerformIsOffsetExecutable(uint64_t offset)
{
	return PerformIsValidOffset(offset);
}


bool BinaryView::PerformIsOffsetBackedByFile(uint64_t offset)
{
	return PerformIsValidOffset(offset);
}


uint64_t BinaryView::PerformGetNextValidOffset(uint64_t offset)
{
	if (offset < PerformGetStart())
		return PerformGetStart();
	return offset;
}


BNEndianness BinaryView::PerformGetDefaultEndianness() const
{
	Ref<Architecture> arch = GetDefaultArchitecture();
	if (arch)
		return arch->GetEndianness();
	return LittleEndian;
}


bool BinaryView::PerformIsRelocatable() const
{
	return false;
}

size_t BinaryView::PerformGetAddressSize() const
{
	Ref<Architecture> arch = GetDefaultArchitecture();
	if (arch)
		return arch->GetAddressSize();
	if (GetEnd() > (1LL << 32))
		return 8;
	return 4;
}


bool BinaryView::PerformSave(FileAccessor* file)
{
	Ref<BinaryView> parent = GetParentView();
	if (parent)
		return parent->Save(file);
	return false;
}


void BinaryView::PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc)
{
	DefineRelocation(arch, info, target, reloc);
}


void BinaryView::PerformDefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> target, uint64_t reloc)
{
	DefineRelocation(arch, info, target, reloc);
}


void BinaryView::NotifyDataWritten(uint64_t offset, size_t len)
{
	BNNotifyDataWritten(m_object, offset, len);
}


void BinaryView::NotifyDataInserted(uint64_t offset, size_t len)
{
	BNNotifyDataInserted(m_object, offset, len);
}


void BinaryView::NotifyDataRemoved(uint64_t offset, uint64_t len)
{
	BNNotifyDataRemoved(m_object, offset, len);
}


Ref<BinaryView> BinaryView::GetParentView() const
{
	BNBinaryView* view = BNGetParentView(m_object);
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


string BinaryView::GetTypeName() const
{
	char* str = BNGetViewType(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


bool BinaryView::IsModified() const
{
	return BNIsViewModified(m_object);
}


bool BinaryView::IsAnalysisChanged() const
{
	return m_file->IsAnalysisChanged();
}


bool BinaryView::CreateDatabase(const string& path, Ref<SaveSettings> settings)
{
	auto parent = GetParentView();
	if (parent)
		return parent->CreateDatabase(path, settings);
	return m_file->CreateDatabase(path, this, settings);
}


bool BinaryView::CreateDatabase(const string& path,
    const function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings)
{
	auto parent = GetParentView();
	if (parent)
		return parent->CreateDatabase(path, settings);
	return m_file->CreateDatabase(path, this, progressCallback, settings);
}


bool BinaryView::SaveAutoSnapshot(Ref<SaveSettings> settings)
{
	return m_file->SaveAutoSnapshot(this, settings);
}


bool BinaryView::SaveAutoSnapshot(
    const function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings)
{
	return m_file->SaveAutoSnapshot(this, progressCallback, settings);
}


void BinaryView::BeginUndoActions()
{
	m_file->BeginUndoActions();
}


void BinaryView::CommitUndoActions()
{
	m_file->CommitUndoActions();
}


bool BinaryView::CanUndo()
{
	return m_file->CanUndo();
}


bool BinaryView::Undo()
{
	return m_file->Undo();
}


bool BinaryView::CanRedo()
{
	return m_file->CanRedo();
}


bool BinaryView::Redo()
{
	return m_file->Redo();
}


string BinaryView::GetCurrentView()
{
	return m_file->GetCurrentView();
}


uint64_t BinaryView::GetCurrentOffset()
{
	return m_file->GetCurrentOffset();
}


bool BinaryView::Navigate(const string& view, uint64_t offset)
{
	return m_file->Navigate(view, offset);
}


DataBuffer BinaryView::ReadBuffer(uint64_t offset, size_t len)
{
	BNDataBuffer* result = BNReadViewBuffer(m_object, offset, len);
	return DataBuffer(result);
}


size_t BinaryView::WriteBuffer(uint64_t offset, const DataBuffer& data)
{
	return BNWriteViewBuffer(m_object, offset, data.GetBufferObject());
}


size_t BinaryView::InsertBuffer(uint64_t offset, const DataBuffer& data)
{
	return BNInsertViewBuffer(m_object, offset, data.GetBufferObject());
}


vector<float> BinaryView::GetEntropy(uint64_t offset, size_t len, size_t blockSize)
{
	if (!blockSize)
		blockSize = len;

	float* entopy = new float[(len / blockSize) + 1];
	len = BNGetEntropy(m_object, offset, len, blockSize, entopy);

	vector<float> result;
	result.reserve(len);
	for (size_t i = 0; i < len; i++)
		result.push_back(entopy[i]);

	delete[] entopy;
	return result;
}


vector<BNModificationStatus> BinaryView::GetModification(uint64_t offset, size_t len)
{
	BNModificationStatus* mod = new BNModificationStatus[len];
	len = BNGetModificationArray(m_object, offset, mod, len);

	vector<BNModificationStatus> result;
	result.reserve(len);
	for (size_t i = 0; i < len; i++)
		result.push_back(mod[i]);

	delete[] mod;
	return result;
}


uint64_t BinaryView::GetEnd() const
{
	return BNGetEndOffset(m_object);
}


bool BinaryView::Save(const string& path)
{
	return BNSaveToFilename(m_object, path.c_str());
}


void BinaryView::DefineRelocation(Architecture* arch, BNRelocationInfo& info, uint64_t target, uint64_t reloc)
{
	BNDefineRelocation(m_object, arch->GetObject(), &info, target, reloc);
}


void BinaryView::DefineRelocation(Architecture* arch, BNRelocationInfo& info, Ref<Symbol> target, uint64_t reloc)
{
	BNDefineSymbolRelocation(m_object, arch->GetObject(), &info, target->GetObject(), reloc);
}


vector<pair<uint64_t, uint64_t>> BinaryView::GetRelocationRanges() const
{
	size_t count = 0;
	BNRange* ranges = BNGetRelocationRanges(m_object, &count);
	vector<pair<uint64_t, uint64_t>> result(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back({ranges[i].start, ranges[i].end});
	}
	BNFreeRelocationRanges(ranges);
	return result;
}


vector<pair<uint64_t, uint64_t>> BinaryView::GetRelocationRangesAtAddress(uint64_t addr) const
{
	size_t count = 0;
	BNRange* ranges = BNGetRelocationRangesAtAddress(m_object, addr, &count);
	vector<pair<uint64_t, uint64_t>> result(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back({ranges[i].start, ranges[i].end});
	}
	BNFreeRelocationRanges(ranges);
	return result;
}


bool BinaryView::RangeContainsRelocation(uint64_t addr, size_t size) const
{
	return BNRangeContainsRelocation(m_object, addr, size);
}


void BinaryView::RegisterNotification(BinaryDataNotification* notify)
{
	BNRegisterDataNotification(m_object, notify->GetCallbacks());
}


void BinaryView::UnregisterNotification(BinaryDataNotification* notify)
{
	BNUnregisterDataNotification(m_object, notify->GetCallbacks());
}


size_t BinaryView::Read(void* dest, uint64_t offset, size_t len)
{
	return BNReadViewData(m_object, dest, offset, len);
}


size_t BinaryView::Write(uint64_t offset, const void* data, size_t len)
{
	return BNWriteViewData(m_object, offset, data, len);
}


size_t BinaryView::Insert(uint64_t offset, const void* data, size_t len)
{
	return BNInsertViewData(m_object, offset, data, len);
}


size_t BinaryView::Remove(uint64_t offset, uint64_t len)
{
	return BNRemoveViewData(m_object, offset, len);
}


BNModificationStatus BinaryView::GetModification(uint64_t offset)
{
	return BNGetModification(m_object, offset);
}


bool BinaryView::IsValidOffset(uint64_t offset) const
{
	return BNIsValidOffset(m_object, offset);
}


bool BinaryView::IsOffsetReadable(uint64_t offset) const
{
	return BNIsOffsetReadable(m_object, offset);
}


bool BinaryView::IsOffsetWritable(uint64_t offset) const
{
	return BNIsOffsetWritable(m_object, offset);
}


bool BinaryView::IsOffsetExecutable(uint64_t offset) const
{
	return BNIsOffsetExecutable(m_object, offset);
}


bool BinaryView::IsOffsetBackedByFile(uint64_t offset) const
{
	return BNIsOffsetBackedByFile(m_object, offset);
}


bool BinaryView::IsOffsetCodeSemantics(uint64_t offset) const
{
	return BNIsOffsetCodeSemantics(m_object, offset);
}


bool BinaryView::IsOffsetExternSemantics(uint64_t offset) const
{
	return BNIsOffsetExternSemantics(m_object, offset);
}


bool BinaryView::IsOffsetWritableSemantics(uint64_t offset) const
{
	return BNIsOffsetWritableSemantics(m_object, offset);
}


uint64_t BinaryView::GetNextValidOffset(uint64_t offset) const
{
	return BNGetNextValidOffset(m_object, offset);
}


uint64_t BinaryView::GetStart() const
{
	return BNGetStartOffset(m_object);
}


uint64_t BinaryView::GetLength() const
{
	return BNGetViewLength(m_object);
}


uint64_t BinaryView::GetEntryPoint() const
{
	return BNGetEntryPoint(m_object);
}


Ref<Architecture> BinaryView::GetDefaultArchitecture() const
{
	BNArchitecture* arch = BNGetDefaultArchitecture(m_object);
	if (!arch)
		return nullptr;
	return new CoreArchitecture(arch);
}


void BinaryView::SetDefaultArchitecture(Architecture* arch)
{
	if (arch)
		BNSetDefaultArchitecture(m_object, arch->GetObject());
	else
		BNSetDefaultArchitecture(m_object, nullptr);
}


Ref<Platform> BinaryView::GetDefaultPlatform() const
{
	BNPlatform* platform = BNGetDefaultPlatform(m_object);
	if (!platform)
		return nullptr;
	return new Platform(platform);
}


void BinaryView::SetDefaultPlatform(Platform* platform)
{
	if (platform)
		BNSetDefaultPlatform(m_object, platform->GetObject());
	else
		BNSetDefaultPlatform(m_object, nullptr);
}


BNEndianness BinaryView::GetDefaultEndianness() const
{
	return BNGetDefaultEndianness(m_object);
}


bool BinaryView::IsRelocatable() const
{
	return BNIsRelocatable(m_object);
}


size_t BinaryView::GetAddressSize() const
{
	return BNGetViewAddressSize(m_object);
}


bool BinaryView::IsExecutable() const
{
	return BNIsExecutableView(m_object);
}


bool BinaryView::Save(FileAccessor* file)
{
	return BNSaveToFile(m_object, file->GetCallbacks());
}


void BinaryView::AddAnalysisOption(const string& name)
{
	BNAddAnalysisOption(m_object, name.c_str());
}


void BinaryView::AddFunctionForAnalysis(Platform* platform, uint64_t addr)
{
	BNAddFunctionForAnalysis(m_object, platform->GetObject(), addr);
}


void BinaryView::AddEntryPointForAnalysis(Platform* platform, uint64_t addr)
{
	BNAddEntryPointForAnalysis(m_object, platform->GetObject(), addr);
}


void BinaryView::RemoveAnalysisFunction(Function* func)
{
	BNRemoveAnalysisFunction(m_object, func->GetObject());
}


void BinaryView::CreateUserFunction(Platform* platform, uint64_t start)
{
	BNCreateUserFunction(m_object, platform->GetObject(), start);
}


void BinaryView::RemoveUserFunction(Function* func)
{
	BNRemoveUserFunction(m_object, func->GetObject());
}


bool BinaryView::HasInitialAnalysis()
{
	return BNHasInitialAnalysis(m_object);
}


void BinaryView::SetAnalysisHold(bool enable)
{
	BNSetAnalysisHold(m_object, enable);
}


void BinaryView::UpdateAnalysisAndWait()
{
	BNUpdateAnalysisAndWait(m_object);
}


void BinaryView::UpdateAnalysis()
{
	BNUpdateAnalysis(m_object);
}


void BinaryView::AbortAnalysis()
{
	BNAbortAnalysis(m_object);
}


void BinaryView::DefineDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNDefineDataVariable(m_object, addr, &tc);
}


void BinaryView::DefineUserDataVariable(uint64_t addr, const Confidence<Ref<Type>>& type)
{
	BNTypeWithConfidence tc;
	tc.type = type->GetObject();
	tc.confidence = type.GetConfidence();
	BNDefineUserDataVariable(m_object, addr, &tc);
}


void BinaryView::UndefineDataVariable(uint64_t addr)
{
	BNUndefineDataVariable(m_object, addr);
}


void BinaryView::UndefineUserDataVariable(uint64_t addr)
{
	BNUndefineUserDataVariable(m_object, addr);
}


map<uint64_t, DataVariable> BinaryView::GetDataVariables()
{
	size_t count;
	BNDataVariable* vars = BNGetDataVariables(m_object, &count);

	map<uint64_t, DataVariable> result;
	for (size_t i = 0; i < count; i++)
	{
		result.emplace(piecewise_construct, forward_as_tuple(vars[i].address),
		    forward_as_tuple(vars[i].address,
		        Confidence<Ref<Type>>(new Type(BNNewTypeReference(vars[i].type)), vars[i].typeConfidence),
		        vars[i].autoDiscovered));
	}

	BNFreeDataVariables(vars, count);
	return result;
}


bool BinaryView::GetDataVariableAtAddress(uint64_t addr, DataVariable& var)
{
	var.address = 0;
	var.type = Confidence<Ref<Type>>(nullptr, 0);
	var.autoDiscovered = false;

	BNDataVariable result;
	if (!BNGetDataVariableAtAddress(m_object, addr, &result))
		return false;

	var.address = result.address;
	var.type = Confidence<Ref<Type>>(new Type(BNNewTypeReference(result.type)), result.typeConfidence);
	var.autoDiscovered = result.autoDiscovered;
	return true;
}


vector<Ref<Function>> BinaryView::GetAnalysisFunctionList()
{
	size_t count;
	BNFunction** list = BNGetAnalysisFunctionList(m_object, &count);

	vector<Ref<Function>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Function(BNNewFunctionReference(list[i])));

	BNFreeFunctionList(list, count);

	return result;
}


AnalysisInfo BinaryView::GetAnalysisInfo()
{
	AnalysisInfo result;
	BNAnalysisInfo* info = BNGetAnalysisInfo(m_object);
	result.state = info->state;
	result.analysisTime = info->analysisTime;
	result.activeInfo.reserve(info->count);
	for (size_t i = 0; i < info->count; i++)
		result.activeInfo.emplace_back(new Function(BNNewFunctionReference(info->activeInfo[i].func)),
		    info->activeInfo[i].analysisTime, info->activeInfo[i].submitCount, info->activeInfo[i].updateCount);
	BNFreeAnalysisInfo(info);
	return result;
}


bool BinaryView::HasFunctions() const
{
	return BNHasFunctions(m_object);
}


bool BinaryView::HasSymbols() const
{
	return BNHasSymbols(m_object);
}


bool BinaryView::HasDataVariables() const
{
	return BNHasDataVariables(m_object);
}


Ref<Function> BinaryView::GetAnalysisFunction(Platform* platform, uint64_t addr)
{
	BNFunction* func = BNGetAnalysisFunction(m_object, platform->GetObject(), addr);
	if (!func)
		return nullptr;
	return new Function(func);
}


Ref<Function> BinaryView::GetRecentAnalysisFunctionForAddress(uint64_t addr)
{
	BNFunction* func = BNGetRecentAnalysisFunctionForAddress(m_object, addr);
	if (!func)
		return nullptr;
	return new Function(func);
}


vector<Ref<Function>> BinaryView::GetAnalysisFunctionsForAddress(uint64_t addr)
{
	size_t count;
	BNFunction** list = BNGetAnalysisFunctionsForAddress(m_object, addr, &count);

	vector<Ref<Function>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Function(BNNewFunctionReference(list[i])));

	BNFreeFunctionList(list, count);
	return result;
}


vector<Ref<Function>> BinaryView::GetAnalysisFunctionsContainingAddress(uint64_t addr)
{
	size_t count;
	BNFunction** list = BNGetAnalysisFunctionsContainingAddress(m_object, addr, &count);

	vector<Ref<Function>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Function(BNNewFunctionReference(list[i])));

	BNFreeFunctionList(list, count);
	return result;
}


Ref<Function> BinaryView::GetAnalysisEntryPoint()
{
	BNFunction* func = BNGetAnalysisEntryPoint(m_object);
	if (!func)
		return nullptr;
	return new Function(func);
}


Ref<BasicBlock> BinaryView::GetRecentBasicBlockForAddress(uint64_t addr)
{
	BNBasicBlock* block = BNGetRecentBasicBlockForAddress(m_object, addr);
	if (!block)
		return nullptr;
	return new BasicBlock(block);
}


vector<Ref<BasicBlock>> BinaryView::GetBasicBlocksForAddress(uint64_t addr)
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlocksForAddress(m_object, addr, &count);

	vector<Ref<BasicBlock>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


vector<Ref<BasicBlock>> BinaryView::GetBasicBlocksStartingAtAddress(uint64_t addr)
{
	size_t count;
	BNBasicBlock** blocks = BNGetBasicBlocksStartingAtAddress(m_object, addr, &count);

	vector<Ref<BasicBlock>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new BasicBlock(BNNewBasicBlockReference(blocks[i])));

	BNFreeBasicBlockList(blocks, count);
	return result;
}


vector<ReferenceSource> BinaryView::GetCodeReferences(uint64_t addr)
{
	size_t count;
	BNReferenceSource* refs = BNGetCodeReferences(m_object, addr, &count);

	vector<ReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		ReferenceSource src;
		src.func = new Function(BNNewFunctionReference(refs[i].func));
		src.arch = new CoreArchitecture(refs[i].arch);
		src.addr = refs[i].addr;
		result.push_back(src);
	}

	BNFreeCodeReferences(refs, count);
	return result;
}


vector<ReferenceSource> BinaryView::GetCodeReferences(uint64_t addr, uint64_t len)
{
	size_t count;
	BNReferenceSource* refs = BNGetCodeReferencesInRange(m_object, addr, len, &count);

	vector<ReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		ReferenceSource src;
		src.func = new Function(BNNewFunctionReference(refs[i].func));
		src.arch = new CoreArchitecture(refs[i].arch);
		src.addr = refs[i].addr;
		result.push_back(src);
	}

	BNFreeCodeReferences(refs, count);
	return result;
}


vector<uint64_t> BinaryView::GetCodeReferencesFrom(ReferenceSource src)
{
	size_t count;
	BNReferenceSource _src {src.func->m_object, src.arch->m_object, src.addr};
	uint64_t* refs = BNGetCodeReferencesFrom(m_object, &_src, &count);
	vector<uint64_t> result(refs, &refs[count]);
	BNFreeAddressList(refs);
	return result;
}


vector<uint64_t> BinaryView::GetCodeReferencesFrom(ReferenceSource src, uint64_t len)
{
	size_t count;
	BNReferenceSource _src {src.func->m_object, src.arch->m_object, src.addr};
	uint64_t* refs = BNGetCodeReferencesFromInRange(m_object, &_src, len, &count);
	vector<uint64_t> result(refs, &refs[count]);
	BNFreeAddressList(refs);
	return result;
}


vector<uint64_t> BinaryView::GetDataReferences(uint64_t addr)
{
	size_t count;
	uint64_t* refs = BNGetDataReferences(m_object, addr, &count);
	vector<uint64_t> result(refs, &refs[count]);
	BNFreeDataReferences(refs);
	return result;
}


vector<uint64_t> BinaryView::GetDataReferences(uint64_t addr, uint64_t len)
{
	size_t count;
	uint64_t* refs = BNGetDataReferencesInRange(m_object, addr, len, &count);
	vector<uint64_t> result(refs, &refs[count]);
	BNFreeDataReferences(refs);
	return result;
}


vector<uint64_t> BinaryView::GetDataReferencesFrom(uint64_t addr)
{
	size_t count;
	uint64_t* refs = BNGetDataReferencesFrom(m_object, addr, &count);
	vector<uint64_t> result(refs, &refs[count]);
	BNFreeDataReferences(refs);
	return result;
}


vector<uint64_t> BinaryView::GetDataReferencesFrom(uint64_t addr, uint64_t len)
{
	size_t count;
	uint64_t* refs = BNGetDataReferencesFromInRange(m_object, addr, len, &count);
	vector<uint64_t> result(refs, &refs[count]);
	BNFreeDataReferences(refs);
	return result;
}


void BinaryView::AddUserDataReference(uint64_t fromAddr, uint64_t toAddr)
{
	BNAddUserDataReference(m_object, fromAddr, toAddr);
}


void BinaryView::RemoveUserDataReference(uint64_t fromAddr, uint64_t toAddr)
{
	BNRemoveUserDataReference(m_object, fromAddr, toAddr);
}


vector<ReferenceSource> BinaryView::GetCodeReferencesForType(const QualifiedName& type)
{
	size_t count;

	BNQualifiedName nameObj = type.GetAPIObject();
	BNReferenceSource* refs = BNGetCodeReferencesForType(m_object, &nameObj, &count);
	QualifiedName::FreeAPIObject(&nameObj);

	vector<ReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		ReferenceSource src;
		src.func = new Function(BNNewFunctionReference(refs[i].func));
		src.arch = new CoreArchitecture(refs[i].arch);
		src.addr = refs[i].addr;
		result.push_back(src);
	}

	BNFreeCodeReferences(refs, count);
	return result;
}


vector<uint64_t> BinaryView::GetDataReferencesForType(const QualifiedName& type)
{
	size_t count;
	BNQualifiedName nameObj = type.GetAPIObject();
	uint64_t* refs = BNGetDataReferencesForType(m_object, &nameObj, &count);
	QualifiedName::FreeAPIObject(&nameObj);

	vector<uint64_t> result(refs, &refs[count]);
	BNFreeDataReferences(refs);
	return result;
}


vector<TypeReferenceSource> BinaryView::GetTypeReferencesForType(const QualifiedName& type)
{
	size_t count;

	BNQualifiedName nameObj = type.GetAPIObject();
	BNTypeReferenceSource* refs = BNGetTypeReferencesForType(m_object, &nameObj, &count);
	QualifiedName::FreeAPIObject(&nameObj);

	vector<TypeReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		TypeReferenceSource src;
		src.name = QualifiedName::FromAPIObject(&refs[i].name);
		src.offset = refs[i].offset;
		src.type = refs[i].type;
		result.push_back(src);
	}

	BNFreeTypeReferences(refs, count);
	return result;
}


vector<TypeFieldReference> BinaryView::GetCodeReferencesForTypeField(const QualifiedName& type, uint64_t offset)
{
	size_t count;
	BNQualifiedName nameObj = type.GetAPIObject();
	BNTypeFieldReference* refs = BNGetCodeReferencesForTypeField(m_object, &nameObj, offset, &count);
	QualifiedName::FreeAPIObject(&nameObj);

	vector<TypeFieldReference> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		TypeFieldReference src;
		src.func = new Function(BNNewFunctionReference(refs[i].func));
		src.arch = new CoreArchitecture(refs[i].arch);
		src.addr = refs[i].addr;
		src.size = refs[i].size;
		BNTypeWithConfidence& tc = refs[i].incomingType;
		Ref<Type> type = tc.type ? new Type(BNNewTypeReference(tc.type)) : nullptr;
		src.incomingType = Confidence<Ref<Type>>(type, tc.confidence);
		result.push_back(src);
	}

	BNFreeTypeFieldReferences(refs, count);
	return result;
}


vector<uint64_t> BinaryView::GetDataReferencesForTypeField(const QualifiedName& type, uint64_t offset)
{
	size_t count;
	BNQualifiedName nameObj = type.GetAPIObject();
	uint64_t* refs = BNGetDataReferencesForTypeField(m_object, &nameObj, offset, &count);
	QualifiedName::FreeAPIObject(&nameObj);

	vector<uint64_t> result(refs, &refs[count]);
	BNFreeDataReferences(refs);
	return result;
}


vector<TypeReferenceSource> BinaryView::GetTypeReferencesForTypeField(const QualifiedName& type, uint64_t offset)
{
	size_t count;
	BNQualifiedName nameObj = type.GetAPIObject();
	BNTypeReferenceSource* refs = BNGetTypeReferencesForTypeField(m_object, &nameObj, offset, &count);
	QualifiedName::FreeAPIObject(&nameObj);

	vector<TypeReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		TypeReferenceSource src;
		src.name = QualifiedName::FromAPIObject(&refs[i].name);
		src.offset = refs[i].offset;
		src.type = refs[i].type;
		result.push_back(src);
	}

	BNFreeTypeReferences(refs, count);
	return result;
}


vector<TypeReferenceSource> BinaryView::GetCodeReferencesForTypeFrom(ReferenceSource src)
{
	size_t count;
	BNReferenceSource _src {src.func->m_object, src.arch->m_object, src.addr};
	BNTypeReferenceSource* refs = BNGetCodeReferencesForTypeFrom(m_object, &_src, &count);

	vector<TypeReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		TypeReferenceSource src;
		src.name = QualifiedName::FromAPIObject(&refs[i].name);
		src.offset = refs[i].offset;
		src.type = refs[i].type;
		result.push_back(src);
	}

	BNFreeTypeReferences(refs, count);
	return result;
}


vector<TypeReferenceSource> BinaryView::GetCodeReferencesForTypeFrom(ReferenceSource src, uint64_t len)
{
	size_t count;
	BNReferenceSource _src {src.func->m_object, src.arch->m_object, src.addr};
	BNTypeReferenceSource* refs = BNGetCodeReferencesForTypeFromInRange(m_object, &_src, len, &count);

	vector<TypeReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		TypeReferenceSource src;
		src.name = QualifiedName::FromAPIObject(&refs[i].name);
		src.offset = refs[i].offset;
		src.type = refs[i].type;
		result.push_back(src);
	}

	BNFreeTypeReferences(refs, count);
	return result;
}

vector<TypeReferenceSource> BinaryView::GetCodeReferencesForTypeFieldFrom(ReferenceSource src)
{
	size_t count;
	BNReferenceSource _src {src.func->m_object, src.arch->m_object, src.addr};
	BNTypeReferenceSource* refs = BNGetCodeReferencesForTypeFieldsFrom(m_object, &_src, &count);

	vector<TypeReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		TypeReferenceSource src;
		src.name = QualifiedName::FromAPIObject(&refs[i].name);
		src.offset = refs[i].offset;
		src.type = refs[i].type;
		result.push_back(src);
	}

	BNFreeTypeReferences(refs, count);
	return result;
}


vector<TypeReferenceSource> BinaryView::GetCodeReferencesForTypeFieldFrom(ReferenceSource src, uint64_t len)
{
	size_t count;
	BNReferenceSource _src {src.func->m_object, src.arch->m_object, src.addr};
	BNTypeReferenceSource* refs = BNGetCodeReferencesForTypeFieldsFromInRange(m_object, &_src, len, &count);

	vector<TypeReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		TypeReferenceSource src;
		src.name = QualifiedName::FromAPIObject(&refs[i].name);
		src.offset = refs[i].offset;
		src.type = refs[i].type;
		result.push_back(src);
	}

	BNFreeTypeReferences(refs, count);
	return result;
}


vector<uint64_t> BinaryView::GetAllFieldsReferenced(const QualifiedName& type)
{
	size_t count;
	BNQualifiedName nameObj = type.GetAPIObject();
	uint64_t* fields = BNGetAllFieldsReferenced(m_object, &nameObj, &count);

	vector<uint64_t> result(fields, &fields[count]);
	// Data refs and the fields above are both an array of uint64_t, so they can be freed in
	// the same way
	BNFreeDataReferences(fields);
	return result;
}


std::map<uint64_t, std::vector<size_t>> BinaryView::GetAllSizesReferenced(const QualifiedName& type)
{
	size_t count;
	BNQualifiedName nameObj = type.GetAPIObject();
	BNTypeFieldReferenceSizeInfo* fields = BNGetAllSizesReferenced(m_object, &nameObj, &count);

	std::map<uint64_t, std::vector<size_t>> result;
	for (size_t i = 0; i < count; i++)
	{
		auto& sizes = result[fields[i].offset];
		for (size_t j = 0; j < fields[i].count; j++)
		{
			sizes.push_back(fields[i].sizes[j]);
		}
	}

	BNFreeTypeFieldReferenceSizeInfo(fields, count);
	return result;
}


std::map<uint64_t, std::vector<Confidence<Ref<Type>>>> BinaryView::GetAllTypesReferenced(const QualifiedName& type)
{
	size_t count;
	BNQualifiedName nameObj = type.GetAPIObject();
	BNTypeFieldReferenceTypeInfo* fields = BNGetAllTypesReferenced(m_object, &nameObj, &count);

	std::map<uint64_t, std::vector<Confidence<Ref<Type>>>> result;
	for (size_t i = 0; i < count; i++)
	{
		auto& types = result[fields[i].offset];
		for (size_t j = 0; j < fields[i].count; j++)
		{
			BNTypeWithConfidence tc = fields[i].types[j];
			Ref<Type> type = tc.type ? new Type(BNNewTypeReference(tc.type)) : nullptr;
			types.push_back(Confidence<Ref<Type>>(type, tc.confidence));
		}
	}

	BNFreeTypeFieldReferenceTypeInfo(fields, count);
	return result;
}


std::vector<size_t> BinaryView::GetSizesReferenced(const QualifiedName& type, uint64_t offset)
{
	size_t count;
	BNQualifiedName nameObj = type.GetAPIObject();
	size_t* refs = BNGetSizesReferenced(m_object, &nameObj, offset, &count);

	std::vector<size_t> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result[i] = refs[i];

	BNFreeTypeFieldReferenceSizes(refs, count);
	return result;
}


std::vector<Confidence<Ref<Type>>> BinaryView::GetTypesReferenced(const QualifiedName& type, uint64_t offset)
{
	size_t count;
	BNQualifiedName nameObj = type.GetAPIObject();
	BNTypeWithConfidence* types = BNGetTypesReferenced(m_object, &nameObj, offset, &count);

	std::vector<Confidence<Ref<Type>>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		BNTypeWithConfidence tc = types[i];
		Ref<Type> type = tc.type ? new Type(BNNewTypeReference(tc.type)) : nullptr;
		result.push_back(Confidence<Ref<Type>>(type, tc.confidence));
	}

	BNFreeTypeFieldReferenceTypes(types, count);
	return result;
}


vector<uint64_t> BinaryView::GetCallees(ReferenceSource callSite)
{
	size_t count;
	BNReferenceSource src {callSite.func->m_object, callSite.arch->m_object, callSite.addr};
	uint64_t* refs = BNGetCallees(m_object, &src, &count);
	vector<uint64_t> result(refs, &refs[count]);
	BNFreeAddressList(refs);
	return result;
}


vector<ReferenceSource> BinaryView::GetCallers(uint64_t addr)
{
	size_t count;
	BNReferenceSource* refs = BNGetCallers(m_object, addr, &count);

	vector<ReferenceSource> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		ReferenceSource src;
		src.func = new Function(BNNewFunctionReference(refs[i].func));
		src.arch = new CoreArchitecture(refs[i].arch);
		src.addr = refs[i].addr;
		result.push_back(src);
	}

	BNFreeCodeReferences(refs, count);
	return result;
}


Ref<Symbol> BinaryView::GetSymbolByAddress(uint64_t addr, const NameSpace& nameSpace)
{
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol* sym = BNGetSymbolByAddress(m_object, addr, &ns);
	NameSpace::FreeAPIObject(&ns);
	if (!sym)
		return nullptr;
	return new Symbol(sym);
}


Ref<Symbol> BinaryView::GetSymbolByRawName(const string& name, const NameSpace& nameSpace)
{
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol* sym = BNGetSymbolByRawName(m_object, name.c_str(), &ns);
	NameSpace::FreeAPIObject(&ns);
	if (!sym)
		return nullptr;
	return new Symbol(sym);
}


vector<Ref<Symbol>> BinaryView::GetSymbolsByName(const string& name, const NameSpace& nameSpace)
{
	size_t count;
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol** syms = BNGetSymbolsByName(m_object, name.c_str(), &count, &ns);
	NameSpace::FreeAPIObject(&ns);

	vector<Ref<Symbol>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbols(const NameSpace& nameSpace)
{
	size_t count;
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol** syms = BNGetSymbols(m_object, &count, &ns);
	NameSpace::FreeAPIObject(&ns);

	vector<Ref<Symbol>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbols(uint64_t start, uint64_t len, const NameSpace& nameSpace)
{
	size_t count;
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol** syms = BNGetSymbolsInRange(m_object, start, len, &count, &ns);
	NameSpace::FreeAPIObject(&ns);

	vector<Ref<Symbol>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbolsOfType(BNSymbolType type, const NameSpace& nameSpace)
{
	size_t count;
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol** syms = BNGetSymbolsOfType(m_object, type, &count, &ns);
	NameSpace::FreeAPIObject(&ns);

	vector<Ref<Symbol>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


vector<Ref<Symbol>> BinaryView::GetSymbolsOfType(
    BNSymbolType type, uint64_t start, uint64_t len, const NameSpace& nameSpace)
{
	size_t count;
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol** syms = BNGetSymbolsOfTypeInRange(m_object, type, start, len, &count, &ns);
	NameSpace::FreeAPIObject(&ns);

	vector<Ref<Symbol>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


std::vector<Ref<Symbol>> BinaryView::GetVisibleSymbols(const NameSpace& nameSpace)
{
	size_t count;
	BNNameSpace ns = nameSpace.GetAPIObject();
	BNSymbol** syms = BNGetVisibleSymbols(m_object, &count, &ns);
	NameSpace::FreeAPIObject(&ns);

	vector<Ref<Symbol>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Symbol(BNNewSymbolReference(syms[i])));

	BNFreeSymbolList(syms, count);
	return result;
}


void BinaryView::DefineAutoSymbol(Ref<Symbol> sym)
{
	BNDefineAutoSymbol(m_object, sym->GetObject());
}


Ref<Symbol> BinaryView::DefineAutoSymbolAndVariableOrFunction(Ref<Platform> platform, Ref<Symbol> sym, Ref<Type> type)
{
	BNSymbol* result = BNDefineAutoSymbolAndVariableOrFunction(
	    m_object, platform ? platform->GetObject() : nullptr, sym->GetObject(), type ? type->GetObject() : nullptr);
	if (!result)
		return nullptr;
	return new Symbol(result);
}


void BinaryView::UndefineAutoSymbol(Ref<Symbol> sym)
{
	BNUndefineAutoSymbol(m_object, sym->GetObject());
}


void BinaryView::DefineUserSymbol(Ref<Symbol> sym)
{
	BNDefineUserSymbol(m_object, sym->GetObject());
}


void BinaryView::UndefineUserSymbol(Ref<Symbol> sym)
{
	BNUndefineUserSymbol(m_object, sym->GetObject());
}


void BinaryView::DefineImportedFunction(Ref<Symbol> importAddressSym, Ref<Function> func, Ref<Type> type)
{
	BNDefineImportedFunction(
	    m_object, importAddressSym->GetObject(), func->GetObject(), type ? type->GetObject() : nullptr);
}


void BinaryView::BeginBulkModifySymbols()
{
	BNBeginBulkModifySymbols(m_object);
}


void BinaryView::EndBulkModifySymbols()
{
	BNEndBulkModifySymbols(m_object);
}


void BinaryView::AddTagType(Ref<TagType> tagType)
{
	BNAddTagType(m_object, tagType->GetObject());
}


void BinaryView::RemoveTagType(Ref<TagType> tagType)
{
	BNRemoveTagType(m_object, tagType->GetObject());
}


Ref<TagType> BinaryView::GetTagType(const std::string& name)
{
	return GetTagTypeByName(name);
}


Ref<TagType> BinaryView::GetTagType(const std::string& name, TagType::Type type)
{
	return GetTagTypeByName(name, type);
}


Ref<TagType> BinaryView::GetTagTypeByName(const std::string& name)
{
	BNTagType* tagType = BNGetTagType(m_object, name.c_str());
	if (!tagType)
		return nullptr;

	return Ref<TagType>(new TagType(tagType));
}


Ref<TagType> BinaryView::GetTagTypeByName(const std::string& name, TagType::Type type)
{
	BNTagType* tagType = BNGetTagTypeWithType(m_object, name.c_str(), type);
	if (!tagType)
		return nullptr;

	return Ref<TagType>(new TagType(tagType));
}


Ref<TagType> BinaryView::GetTagTypeById(const std::string& name)
{
	BNTagType* tagType = BNGetTagTypeById(m_object, name.c_str());
	if (!tagType)
		return nullptr;

	return Ref<TagType>(new TagType(tagType));
}


Ref<TagType> BinaryView::GetTagTypeById(const std::string& name, TagType::Type type)
{
	BNTagType* tagType = BNGetTagTypeByIdWithType(m_object, name.c_str(), type);
	if (!tagType)
		return nullptr;

	return Ref<TagType>(new TagType(tagType));
}


std::vector<Ref<TagType>> BinaryView::GetTagTypes()
{
	size_t count;
	BNTagType** tagTypes = BNGetTagTypes(m_object, &count);

	std::vector<Ref<TagType>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new TagType(BNNewTagTypeReference(tagTypes[i])));
	}
	BNFreeTagTypeList(tagTypes, count);

	return result;
}


void BinaryView::AddTag(Ref<Tag> tag, bool user)
{
	BNAddTag(m_object, tag->GetObject(), user);
}


void BinaryView::RemoveTag(Ref<Tag> tag, bool user)
{
	BNRemoveTag(m_object, tag->GetObject(), user);
}


Ref<Tag> BinaryView::GetTag(const string& tagId)
{
	BNTag* tag = BNGetTag(m_object, tagId.c_str());
	if (!tag)
		return nullptr;

	return Ref<Tag>(new Tag(tag));
}


std::vector<TagReference> BinaryView::GetAllTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetAllTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> BinaryView::GetAllAddressTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetAllAddressTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> BinaryView::GetAllFunctionTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetAllFunctionTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> BinaryView::GetAllTagReferencesOfType(Ref<TagType> tagType)
{
	size_t count;
	BNTagReference* refs = BNGetAllTagReferencesOfType(m_object, tagType->GetObject(), &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> BinaryView::GetTagReferencesOfType(Ref<TagType> tagType)
{
	size_t count;
	BNTagReference* refs = BNGetTagReferencesOfType(m_object, tagType->GetObject(), &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


size_t BinaryView::GetAllTagReferencesOfTypeCount(Ref<TagType> tagType)
{
	return BNGetAllTagReferencesOfTypeCount(m_object, tagType->GetObject());
}


std::map<Ref<TagType>, size_t> BinaryView::GetAllTagReferenceTypeCounts()
{
	BNTagType** types;
	size_t* counts;
	size_t count;
	BNGetAllTagReferenceTypeCounts(m_object, &types, &counts, &count);

	std::map<Ref<TagType>, size_t> result;
	for (size_t i = 0; i < count; i++)
	{
		result[new TagType(BNNewTagTypeReference(types[i]))] = counts[i];
	}

	BNFreeTagReferenceTypeCounts(types, counts);
	return result;
}


size_t BinaryView::GetTagReferencesOfTypeCount(Ref<TagType> tagType)
{
	return BNGetTagReferencesOfTypeCount(m_object, tagType->GetObject());
}


std::vector<TagReference> BinaryView::GetDataTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetDataTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> BinaryView::GetAutoDataTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetAutoDataTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> BinaryView::GetUserDataTagReferences()
{
	size_t count;
	BNTagReference* refs = BNGetUserDataTagReferences(m_object, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<Ref<Tag>> BinaryView::GetDataTags(uint64_t addr)
{
	size_t count;
	BNTag** tags = BNGetDataTags(m_object, addr, &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> BinaryView::GetAutoDataTags(uint64_t addr)
{
	size_t count;
	BNTag** tags = BNGetAutoDataTags(m_object, addr, &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> BinaryView::GetUserDataTags(uint64_t addr)
{
	size_t count;
	BNTag** tags = BNGetUserDataTags(m_object, addr, &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> BinaryView::GetDataTagsOfType(uint64_t addr, Ref<TagType> tagType)
{
	size_t count;
	BNTag** tags = BNGetDataTagsOfType(m_object, addr, tagType->GetObject(), &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> BinaryView::GetAutoDataTagsOfType(uint64_t addr, Ref<TagType> tagType)
{
	size_t count;
	BNTag** tags = BNGetAutoDataTagsOfType(m_object, addr, tagType->GetObject(), &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<Ref<Tag>> BinaryView::GetUserDataTagsOfType(uint64_t addr, Ref<TagType> tagType)
{
	size_t count;
	BNTag** tags = BNGetUserDataTagsOfType(m_object, addr, tagType->GetObject(), &count);
	return Tag::ConvertAndFreeTagList(tags, count);
}


std::vector<TagReference> BinaryView::GetDataTagsInRange(uint64_t start, uint64_t end)
{
	size_t count;
	BNTagReference* refs = BNGetDataTagsInRange(m_object, start, end, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> BinaryView::GetAutoDataTagsInRange(uint64_t start, uint64_t end)
{
	size_t count;
	BNTagReference* refs = BNGetAutoDataTagsInRange(m_object, start, end, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


std::vector<TagReference> BinaryView::GetUserDataTagsInRange(uint64_t start, uint64_t end)
{
	size_t count;
	BNTagReference* refs = BNGetUserDataTagsInRange(m_object, start, end, &count);
	return TagReference::ConvertAndFreeTagReferenceList(refs, count);
}


void BinaryView::AddAutoDataTag(uint64_t addr, Ref<Tag> tag)
{
	BNAddAutoDataTag(m_object, addr, tag->GetObject());
}


void BinaryView::RemoveAutoDataTag(uint64_t addr, Ref<Tag> tag)
{
	BNRemoveAutoDataTag(m_object, addr, tag->GetObject());
}


void BinaryView::RemoveAutoDataTagsOfType(uint64_t addr, Ref<TagType> tagType)
{
	BNRemoveAutoDataTagsOfType(m_object, addr, tagType->GetObject());
}


void BinaryView::AddUserDataTag(uint64_t addr, Ref<Tag> tag)
{
	BNAddUserDataTag(m_object, addr, tag->GetObject());
}


void BinaryView::RemoveUserDataTag(uint64_t addr, Ref<Tag> tag)
{
	BNRemoveUserDataTag(m_object, addr, tag->GetObject());
}


void BinaryView::RemoveUserDataTagsOfType(uint64_t addr, Ref<TagType> tagType)
{
	BNRemoveUserDataTagsOfType(m_object, addr, tagType->GetObject());
}


void BinaryView::RemoveTagReference(const TagReference& ref)
{
	BNRemoveTagReference(m_object, (BNTagReference)ref);
}


Ref<Tag> BinaryView::CreateAutoDataTag(
    uint64_t addr, const std::string& tagTypeName, const std::string& data, bool unique)
{
	Ref<TagType> tagType = GetTagTypeByName(tagTypeName);
	if (!tagType)
		return nullptr;

	return CreateAutoDataTag(addr, tagType, data, unique);
}


Ref<Tag> BinaryView::CreateUserDataTag(
    uint64_t addr, const std::string& tagTypeName, const std::string& data, bool unique)
{
	Ref<TagType> tagType = GetTagTypeByName(tagTypeName);
	if (!tagType)
		return nullptr;

	return CreateUserDataTag(addr, tagType, data, unique);
}


Ref<Tag> BinaryView::CreateAutoDataTag(uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique)
{
	if (unique)
	{
		auto tags = GetDataTags(addr);
		for (const auto& tag : tags)
		{
			if (tag->GetType() == tagType && tag->GetData() == data)
				return nullptr;
		}
	}

	Ref<Tag> tag = new Tag(tagType, data);
	AddTag(tag);

	AddAutoDataTag(addr, tag);
	return tag;
}


Ref<Tag> BinaryView::CreateUserDataTag(uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique)
{
	if (unique)
	{
		auto tags = GetDataTags(addr);
		for (const auto& tag : tags)
		{
			if (tag->GetType() == tagType && tag->GetData() == data)
				return nullptr;
		}
	}

	Ref<Tag> tag = new Tag(tagType, data);
	AddTag(tag);

	AddUserDataTag(addr, tag);
	return tag;
}

bool BinaryView::CanAssemble(Architecture* arch)
{
	return BNCanAssemble(m_object, arch->GetObject());
}

bool BinaryView::IsNeverBranchPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsNeverBranchPatchAvailable(m_object, arch->GetObject(), addr);
}


bool BinaryView::IsAlwaysBranchPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsAlwaysBranchPatchAvailable(m_object, arch->GetObject(), addr);
}


bool BinaryView::IsInvertBranchPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsInvertBranchPatchAvailable(m_object, arch->GetObject(), addr);
}


bool BinaryView::IsSkipAndReturnZeroPatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsSkipAndReturnZeroPatchAvailable(m_object, arch->GetObject(), addr);
}


bool BinaryView::IsSkipAndReturnValuePatchAvailable(Architecture* arch, uint64_t addr)
{
	return BNIsSkipAndReturnValuePatchAvailable(m_object, arch->GetObject(), addr);
}


bool BinaryView::ConvertToNop(Architecture* arch, uint64_t addr)
{
	return BNConvertToNop(m_object, arch->GetObject(), addr);
}


bool BinaryView::AlwaysBranch(Architecture* arch, uint64_t addr)
{
	return BNAlwaysBranch(m_object, arch->GetObject(), addr);
}


bool BinaryView::InvertBranch(Architecture* arch, uint64_t addr)
{
	return BNInvertBranch(m_object, arch->GetObject(), addr);
}


bool BinaryView::SkipAndReturnValue(Architecture* arch, uint64_t addr, uint64_t value)
{
	return BNSkipAndReturnValue(m_object, arch->GetObject(), addr, value);
}


size_t BinaryView::GetInstructionLength(Architecture* arch, uint64_t addr)
{
	return BNGetInstructionLength(m_object, arch->GetObject(), addr);
}


bool BinaryView::GetStringAtAddress(uint64_t addr, BNStringReference& strRef)
{
	return BNGetStringAtAddress(m_object, addr, &strRef);
}


vector<BNStringReference> BinaryView::GetStrings()
{
	size_t count;
	BNStringReference* strings = BNGetStrings(m_object, &count);
	vector<BNStringReference> result;
	result.insert(result.end(), strings, strings + count);
	BNFreeStringReferenceList(strings);
	return result;
}


vector<BNStringReference> BinaryView::GetStrings(uint64_t start, uint64_t len)
{
	size_t count;
	BNStringReference* strings = BNGetStringsInRange(m_object, start, len, &count);
	vector<BNStringReference> result;
	result.insert(result.end(), strings, strings + count);
	BNFreeStringReferenceList(strings);
	return result;
}


// The caller of this function must hold a reference to the returned Ref<AnalysisCompletionEvent>.
// Otherwise, it can be freed before the callback is triggered, leading to a crash.
Ref<AnalysisCompletionEvent> BinaryView::AddAnalysisCompletionEvent(const function<void()>& callback)
{
	return new AnalysisCompletionEvent(this, callback);
}


BNAnalysisProgress BinaryView::GetAnalysisProgress()
{
	return BNGetAnalysisProgress(m_object);
}


Ref<BackgroundTask> BinaryView::GetBackgroundAnalysisTask()
{
	BNBackgroundTask* task = BNGetBackgroundAnalysisTask(m_object);
	if (!task)
		return nullptr;

	return new BackgroundTask(BNNewBackgroundTaskReference(task));
}


uint64_t BinaryView::GetNextFunctionStartAfterAddress(uint64_t addr)
{
	return BNGetNextFunctionStartAfterAddress(m_object, addr);
}


uint64_t BinaryView::GetNextBasicBlockStartAfterAddress(uint64_t addr)
{
	return BNGetNextBasicBlockStartAfterAddress(m_object, addr);
}


uint64_t BinaryView::GetNextDataAfterAddress(uint64_t addr)
{
	return BNGetNextDataAfterAddress(m_object, addr);
}

uint64_t BinaryView::GetNextDataVariableStartAfterAddress(uint64_t addr)
{
	return BNGetNextDataVariableStartAfterAddress(m_object, addr);
}

uint64_t BinaryView::GetPreviousFunctionStartBeforeAddress(uint64_t addr)
{
	return BNGetPreviousFunctionStartBeforeAddress(m_object, addr);
}


uint64_t BinaryView::GetPreviousBasicBlockStartBeforeAddress(uint64_t addr)
{
	return BNGetPreviousBasicBlockStartBeforeAddress(m_object, addr);
}


uint64_t BinaryView::GetPreviousBasicBlockEndBeforeAddress(uint64_t addr)
{
	return BNGetPreviousBasicBlockEndBeforeAddress(m_object, addr);
}


uint64_t BinaryView::GetPreviousDataBeforeAddress(uint64_t addr)
{
	return BNGetPreviousDataBeforeAddress(m_object, addr);
}

uint64_t BinaryView::GetPreviousDataVariableStartBeforeAddress(uint64_t addr)
{
	return BNGetPreviousDataVariableStartBeforeAddress(m_object, addr);
}


bool BinaryView::ParsePossibleValueSet(
    const string& value, BNRegisterValueType state, PossibleValueSet& result, uint64_t here, string& errors)
{
	BNPossibleValueSet res;
	char* errorStr = nullptr;

	if (!BNParsePossibleValueSet(m_object, value.c_str(), state, &res, here, &errorStr))
	{
		if (!errorStr)
			errors = "";
		else
			errors = errorStr;
		BNFreeString(errorStr);
		return false;
	}

	result = PossibleValueSet::FromAPIObject(res);
	errors = "";
	return true;
}


bool BinaryView::ParseTypeString(const string& text, QualifiedNameAndType& result, string& errors,
    const std::set<QualifiedName>& typesAllowRedefinition)
{
	BNQualifiedNameAndType nt;
	char* errorStr;

	BNQualifiedNameList typesList;
	typesList.count = typesAllowRedefinition.size();
	typesList.names = new BNQualifiedName[typesList.count];
	size_t i = 0;
	for (auto& type : typesAllowRedefinition)
	{
		typesList.names[i] = type.GetAPIObject();
		i++;
	}

	if (!BNParseTypeString(m_object, text.c_str(), &nt, &errorStr, &typesList))
	{
		errors = errorStr;
		BNFreeString(errorStr);
		delete[] typesList.names;
		return false;
	}

	result.name = QualifiedName::FromAPIObject(&nt.name);
	result.type = new Type(BNNewTypeReference(nt.type));
	errors = "";
	BNFreeQualifiedNameAndType(&nt);
	delete[] typesList.names;
	return true;
}


bool BinaryView::ParseTypeString(const string& source, map<QualifiedName, Ref<Type>>& types,
    map<QualifiedName, Ref<Type>>& variables, map<QualifiedName, Ref<Type>>& functions, string& errors,
    const std::set<QualifiedName>& typesAllowRedefinition)
{
	BNTypeParserResult result;
	char* errorStr = nullptr;

	types.clear();
	variables.clear();
	functions.clear();

	BNQualifiedNameList typesList;
	typesList.count = typesAllowRedefinition.size();
	typesList.names = new BNQualifiedName[typesList.count];
	size_t i = 0;
	for (auto& type : typesAllowRedefinition)
	{
		typesList.names[i] = type.GetAPIObject();
		i++;
	}

	vector<const char*> options;
	vector<const char*> includeDirs;

	bool ok = BNParseTypesString(m_object, source.c_str(), options.data(), options.size(),
		includeDirs.data(), includeDirs.size(), &result, &errorStr, &typesList);
	if (errorStr)
	{
		errors = errorStr;
		BNFreeString(errorStr);
	}
	if (!ok)
		return false;

	for (size_t i = 0; i < result.typeCount; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&result.types[i].name);
		types[name] = new Type(BNNewTypeReference(result.types[i].type));
	}
	for (size_t i = 0; i < result.variableCount; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&result.variables[i].name);
		variables[name] = new Type(BNNewTypeReference(result.variables[i].type));
	}
	for (size_t i = 0; i < result.functionCount; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&result.functions[i].name);
		functions[name] = new Type(BNNewTypeReference(result.functions[i].type));
	}
	BNFreeTypeParserResult(&result);
	return true;
}


bool BinaryView::ParseTypesFromSource(const string& source, const vector<string>& options, const vector<string>& includeDirs,
	TypeParserResult& result, string& errors, const std::set<QualifiedName>& typesAllowRedefinition)
{
	BNQualifiedNameList typesList;
	typesList.count = typesAllowRedefinition.size();
	typesList.names = new BNQualifiedName[typesList.count];
	size_t i = 0;
	for (auto& type : typesAllowRedefinition)
	{
		typesList.names[i] = type.GetAPIObject();
		i++;
	}

	vector<const char*> coreOptions;
	for (auto& option : options)
		coreOptions.push_back(option.c_str());

	vector<const char*> coreIncludeDirs;
	for (auto& includeDir : includeDirs)
		coreIncludeDirs.push_back(includeDir.c_str());

	BNTypeParserResult apiResult;
	char* errorStr = nullptr;

	bool ok = BNParseTypesString(m_object, source.c_str(), coreOptions.data(), coreOptions.size(),
		coreIncludeDirs.data(), coreIncludeDirs.size(), &apiResult, &errorStr, &typesList);
	if (errorStr)
	{
		errors = errorStr;
		BNFreeString(errorStr);
	}
	if (!ok)
		return false;

	result.types.clear();
	for (size_t j = 0; j < apiResult.typeCount; ++j)
	{
		result.types.push_back({
			QualifiedName::FromAPIObject(&apiResult.types[j].name),
			new Type(BNNewTypeReference(apiResult.types[j].type)),
			apiResult.types[j].isUser
		});
	}

	result.variables.clear();
	for (size_t j = 0; j < apiResult.variableCount; ++j)
	{
		result.variables.push_back({
			QualifiedName::FromAPIObject(&apiResult.variables[j].name),
			new Type(BNNewTypeReference(apiResult.variables[j].type)),
			apiResult.types[j].isUser
		});
	}

	result.functions.clear();
	for (size_t j = 0; j < apiResult.functionCount; ++j)
	{
		result.functions.push_back({
			QualifiedName::FromAPIObject(&apiResult.functions[j].name),
			new Type(BNNewTypeReference(apiResult.functions[j].type)),
			apiResult.types[j].isUser
		});
	}

	BNFreeTypeParserResult(&apiResult);
	return true;
}


map<QualifiedName, Ref<Type>> BinaryView::GetTypes()
{
	size_t count;
	BNQualifiedNameAndType* types = BNGetAnalysisTypeList(m_object, &count);

	map<QualifiedName, Ref<Type>> result;
	for (size_t i = 0; i < count; i++)
	{
		QualifiedName name = QualifiedName::FromAPIObject(&types[i].name);
		result[name] = new Type(BNNewTypeReference(types[i].type));
	}

	BNFreeTypeList(types, count);
	return result;
}


vector<QualifiedName> BinaryView::GetTypeNames(const string& matching)
{
	size_t count;
	BNQualifiedName* names = BNGetAnalysisTypeNames(m_object, &count, matching.c_str());

	vector<QualifiedName> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(QualifiedName::FromAPIObject(&names[i]));
	}

	BNFreeTypeNameList(names, count);
	return result;
}


Ref<Type> BinaryView::GetTypeByName(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNType* type = BNGetAnalysisTypeByName(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);

	if (!type)
		return nullptr;
	return new Type(BNNewTypeReference(type));
}


Ref<Type> BinaryView::GetTypeByRef(Ref<NamedTypeReference> ref)
{
	BNType* type = BNGetAnalysisTypeByRef(m_object, ref->m_object);
	if (!type)
		return nullptr;
	return new Type(BNNewTypeReference(type));
}


Ref<Type> BinaryView::GetTypeById(const string& id)
{
	BNType* type = BNGetAnalysisTypeById(m_object, id.c_str());
	if (!type)
		return nullptr;
	return new Type(BNNewTypeReference(type));
}


QualifiedName BinaryView::GetTypeNameById(const string& id)
{
	BNQualifiedName name = BNGetAnalysisTypeNameById(m_object, id.c_str());
	QualifiedName result = QualifiedName::FromAPIObject(&name);
	BNFreeQualifiedName(&name);
	return result;
}


string BinaryView::GetTypeId(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	char* id = BNGetAnalysisTypeId(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
	string result = id;
	BNFreeString(id);
	return result;
}


bool BinaryView::IsTypeAutoDefined(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	bool result = BNIsAnalysisTypeAutoDefined(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
	return result;
}


QualifiedName BinaryView::DefineType(const string& id, const QualifiedName& defaultName, Ref<Type> type)
{
	BNQualifiedName nameObj = defaultName.GetAPIObject();
	BNQualifiedName regName = BNDefineAnalysisType(m_object, id.c_str(), &nameObj, type->GetObject());
	QualifiedName::FreeAPIObject(&nameObj);
	QualifiedName result = QualifiedName::FromAPIObject(&regName);
	BNFreeQualifiedName(&regName);
	return result;
}


void BinaryView::DefineUserType(const QualifiedName& name, Ref<Type> type)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNDefineUserAnalysisType(m_object, &nameObj, type->GetObject());
	QualifiedName::FreeAPIObject(&nameObj);
}


struct ProgressCallback
{
	std::function<bool(size_t, size_t)> func;
};


void BinaryView::DefineTypes(const vector<pair<string, QualifiedNameAndType>>& types, std::function<bool(size_t, size_t)> progress)
{
	BNQualifiedNameTypeAndId* apiTypes = new BNQualifiedNameTypeAndId[types.size()];
	for (size_t i = 0; i < types.size(); i++)
	{
		apiTypes[i].name = types[i].second.name.GetAPIObject();
		apiTypes[i].type = types[i].second.type->GetObject();
		apiTypes[i].id = BNAllocString(types[i].first.c_str());
	}

	ProgressCallback cb;
	cb.func = progress;
	BNDefineAnalysisTypes(m_object, apiTypes, types.size(), [](void* ctxt, size_t cur, size_t total) {
		ProgressCallback* cb = (ProgressCallback*)ctxt;
		if (cb->func)
			return cb->func(cur, total);
		return true;
	}, &cb);

	for (size_t i = 0; i < types.size(); i++)
	{
		QualifiedName::FreeAPIObject(&apiTypes[i].name);
		BNFreeString(apiTypes[i].id);
	}
	delete [] apiTypes;
}


void BinaryView::DefineUserTypes(const vector<QualifiedNameAndType>& types, std::function<bool(size_t, size_t)> progress)
{
	BNQualifiedNameAndType* apiTypes = new BNQualifiedNameAndType[types.size()];
	for (size_t i = 0; i < types.size(); i++)
	{
		apiTypes[i].name = types[i].name.GetAPIObject();
		apiTypes[i].type = types[i].type->GetObject();
	}

	ProgressCallback cb;
	cb.func = progress;
	BNDefineUserAnalysisTypes(m_object, apiTypes, types.size(), [](void* ctxt, size_t cur, size_t total) {
		ProgressCallback* cb = (ProgressCallback*)ctxt;
		if (cb->func)
			return cb->func(cur, total);
		return true;
	}, &cb);

	for (size_t i = 0; i < types.size(); i++)
	{
		QualifiedName::FreeAPIObject(&apiTypes[i].name);
	}
	delete [] apiTypes;
}


void BinaryView::UndefineType(const string& id)
{
	BNUndefineAnalysisType(m_object, id.c_str());
}


void BinaryView::UndefineUserType(const QualifiedName& name)
{
	BNQualifiedName nameObj = name.GetAPIObject();
	BNUndefineUserAnalysisType(m_object, &nameObj);
	QualifiedName::FreeAPIObject(&nameObj);
}


void BinaryView::RenameType(const QualifiedName& oldName, const QualifiedName& newName)
{
	BNQualifiedName oldNameObj = oldName.GetAPIObject();
	BNQualifiedName newNameObj = newName.GetAPIObject();
	BNRenameAnalysisType(m_object, &oldNameObj, &newNameObj);
	QualifiedName::FreeAPIObject(&oldNameObj);
	QualifiedName::FreeAPIObject(&newNameObj);
}


void BinaryView::RegisterPlatformTypes(Platform* platform)
{
	BNRegisterPlatformTypes(m_object, platform->GetObject());
}


bool BinaryView::FindNextData(uint64_t start, const DataBuffer& data, uint64_t& result, BNFindFlag flags)
{
	return BNFindNextData(m_object, start, data.GetBufferObject(), &result, flags);
}

bool BinaryView::FindNextText(uint64_t start, const std::string& data, uint64_t& result,
    Ref<DisassemblySettings> settings, BNFindFlag flags, BNFunctionGraphType graph)
{
	return BNFindNextText(m_object, start, data.c_str(), &result, settings->GetObject(), flags, graph);
}

bool BinaryView::FindNextConstant(
    uint64_t start, uint64_t constant, uint64_t& result, Ref<DisassemblySettings> settings, BNFunctionGraphType graph)
{
	return BNFindNextConstant(m_object, start, constant, &result, settings->GetObject(), graph);
}


struct FindProgressCallbackContext
{
	std::function<bool(size_t, size_t)> func;
};


static bool FindProgressCallback(void* ctxt, size_t progress, size_t total)
{
	FindProgressCallbackContext* cb = (FindProgressCallbackContext*)ctxt;
	return cb->func(progress, total);
}


struct MatchCallbackContextForDataBuffer
{
	std::function<bool(uint64_t, const DataBuffer&)> func;
};


static bool MatchCallbackForDataBuffer(void* ctxt, uint64_t addr, BNDataBuffer* buffer)
{
	MatchCallbackContextForDataBuffer* cb = (MatchCallbackContextForDataBuffer*)ctxt;
	return cb->func(addr, DataBuffer(buffer));
}


struct MatchCallbackContextForText
{
	std::function<bool(uint64_t, const string&, const LinearDisassemblyLine&)> func;
};


static bool MatchCallbackForText(void* ctxt, uint64_t addr, const char* buffer, BNLinearDisassemblyLine* line)
{
	MatchCallbackContextForText* cb = (MatchCallbackContextForText*)ctxt;

	LinearDisassemblyLine result = LinearDisassemblyLine::FromAPIObject(line);
	BNFreeLinearDisassemblyLines(line, 1);

	return cb->func(addr, string(buffer), result);
}


struct MatchCallbackContextForConstant
{
	std::function<bool(uint64_t, const LinearDisassemblyLine&)> func;
};


static bool MatchCallbackForConstant(void* ctxt, uint64_t addr, BNLinearDisassemblyLine* line)
{
	MatchCallbackContextForConstant* cb = (MatchCallbackContextForConstant*)ctxt;

	LinearDisassemblyLine result = LinearDisassemblyLine::FromAPIObject(line);
	BNFreeLinearDisassemblyLines(line, 1);

	return cb->func(addr, result);
}


bool BinaryView::FindNextData(uint64_t start, uint64_t end, const DataBuffer& data, uint64_t& addr, BNFindFlag flags,
    const std::function<bool(size_t current, size_t total)>& progress)
{
	FindProgressCallbackContext fp;
	fp.func = progress;
	return BNFindNextDataWithProgress(
	    m_object, start, end, data.GetBufferObject(), &addr, flags, &fp, FindProgressCallback);
}


bool BinaryView::FindNextText(uint64_t start, uint64_t end, const std::string& data, uint64_t& addr,
    Ref<DisassemblySettings> settings, BNFindFlag flags, BNFunctionGraphType graph,
    const std::function<bool(size_t current, size_t total)>& progress)
{
	FindProgressCallbackContext fp;
	fp.func = progress;
	return BNFindNextTextWithProgress(
	    m_object, start, end, data.c_str(), &addr, settings->GetObject(), flags, graph, &fp, FindProgressCallback);
}


bool BinaryView::FindNextConstant(uint64_t start, uint64_t end, uint64_t constant, uint64_t& addr,
    Ref<DisassemblySettings> settings, BNFunctionGraphType graph,
    const std::function<bool(size_t current, size_t total)>& progress)
{
	FindProgressCallbackContext fp;
	fp.func = progress;
	return BNFindNextConstantWithProgress(
	    m_object, start, end, constant, &addr, settings->GetObject(), graph, &fp, FindProgressCallback);
}


bool BinaryView::FindAllData(uint64_t start, uint64_t end, const DataBuffer& data, BNFindFlag flags,
    const std::function<bool(size_t current, size_t total)>& progress,
    const std::function<bool(uint64_t addr, const DataBuffer& match)>& matchCallback)
{
	FindProgressCallbackContext fp;
	fp.func = progress;
	MatchCallbackContextForDataBuffer mc;
	mc.func = matchCallback;
	return BNFindAllDataWithProgress(m_object, start, end, data.GetBufferObject(), flags, &fp, FindProgressCallback,
	    &mc, MatchCallbackForDataBuffer);
}


bool BinaryView::FindAllText(uint64_t start, uint64_t end, const std::string& data, Ref<DisassemblySettings> settings,
    BNFindFlag flags, BNFunctionGraphType graph, const std::function<bool(size_t current, size_t total)>& progress,
    const std::function<bool(uint64_t addr, const std::string& match, const LinearDisassemblyLine& line)>&
        matchCallback)
{
	FindProgressCallbackContext fp;
	fp.func = progress;
	MatchCallbackContextForText mc;
	mc.func = matchCallback;
	return BNFindAllTextWithProgress(m_object, start, end, data.c_str(), settings->GetObject(), flags, graph, &fp,
	    FindProgressCallback, &mc, MatchCallbackForText);
}


bool BinaryView::FindAllConstant(uint64_t start, uint64_t end, uint64_t constant, Ref<DisassemblySettings> settings,
    BNFunctionGraphType graph, const std::function<bool(size_t current, size_t total)>& progress,
    const std::function<bool(uint64_t addr, const LinearDisassemblyLine& line)>& matchCallback)
{
	FindProgressCallbackContext fp;
	fp.func = progress;
	MatchCallbackContextForConstant mc;
	mc.func = matchCallback;
	return BNFindAllConstantWithProgress(m_object, start, end, constant, settings->GetObject(), graph, &fp,
	    FindProgressCallback, &mc, MatchCallbackForConstant);
}


void BinaryView::Reanalyze()
{
	BNReanalyzeAllFunctions(m_object);
}


Ref<Workflow> BinaryView::GetWorkflow() const
{
	BNWorkflow* workflow = BNGetWorkflowForBinaryView(m_object);
	if (!workflow)
		return nullptr;
	return new Workflow(workflow);
}


void BinaryView::ShowPlainTextReport(const string& title, const string& contents)
{
	BNShowPlainTextReport(m_object, title.c_str(), contents.c_str());
}


void BinaryView::ShowMarkdownReport(const string& title, const string& contents, const string& plainText)
{
	BNShowMarkdownReport(m_object, title.c_str(), contents.c_str(), plainText.c_str());
}


void BinaryView::ShowHTMLReport(const string& title, const string& contents, const string& plainText)
{
	BNShowHTMLReport(m_object, title.c_str(), contents.c_str(), plainText.c_str());
}


void BinaryView::ShowGraphReport(const string& title, FlowGraph* graph)
{
	BNShowGraphReport(m_object, title.c_str(), graph->GetObject());
}


bool BinaryView::GetAddressInput(uint64_t& result, const string& prompt, const string& title)
{
	uint64_t currentAddress = 0;
	if (m_file)
		currentAddress = m_file->GetCurrentOffset();
	return BNGetAddressInput(&result, prompt.c_str(), title.c_str(), m_object, currentAddress);
}


bool BinaryView::GetAddressInput(uint64_t& result, const string& prompt, const string& title, uint64_t currentAddress)
{
	return BNGetAddressInput(&result, prompt.c_str(), title.c_str(), m_object, currentAddress);
}


void BinaryView::AddAutoSegment(
    uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags)
{
	BNAddAutoSegment(m_object, start, length, dataOffset, dataLength, flags);
}


void BinaryView::RemoveAutoSegment(uint64_t start, uint64_t length)
{
	BNRemoveAutoSegment(m_object, start, length);
}


void BinaryView::AddUserSegment(
    uint64_t start, uint64_t length, uint64_t dataOffset, uint64_t dataLength, uint32_t flags)
{
	BNAddUserSegment(m_object, start, length, dataOffset, dataLength, flags);
}


void BinaryView::RemoveUserSegment(uint64_t start, uint64_t length)
{
	BNRemoveUserSegment(m_object, start, length);
}


vector<Ref<Segment>> BinaryView::GetSegments()
{
	size_t count;
	BNSegment** segments = BNGetSegments(m_object, &count);

	vector<Ref<Segment>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Segment(BNNewSegmentReference(segments[i])));

	BNFreeSegmentList(segments, count);
	return result;
}


Ref<Segment> BinaryView::GetSegmentAt(uint64_t addr)
{
	BNSegment* segment = BNGetSegmentAt(m_object, addr);
	if (!segment)
		return nullptr;

	return new Segment(BNNewSegmentReference(segment));
}


bool BinaryView::GetAddressForDataOffset(uint64_t offset, uint64_t& addr)
{
	return BNGetAddressForDataOffset(m_object, offset, &addr);
}


void BinaryView::AddAutoSection(const string& name, uint64_t start, uint64_t length, BNSectionSemantics semantics,
    const string& type, uint64_t align, uint64_t entrySize, const string& linkedSection, const string& infoSection,
    uint64_t infoData)
{
	BNAddAutoSection(m_object, name.c_str(), start, length, semantics, type.c_str(), align, entrySize,
	    linkedSection.c_str(), infoSection.c_str(), infoData);
}


void BinaryView::RemoveAutoSection(const string& name)
{
	BNRemoveAutoSection(m_object, name.c_str());
}


void BinaryView::AddUserSection(const string& name, uint64_t start, uint64_t length, BNSectionSemantics semantics,
    const string& type, uint64_t align, uint64_t entrySize, const string& linkedSection, const string& infoSection,
    uint64_t infoData)
{
	BNAddUserSection(m_object, name.c_str(), start, length, semantics, type.c_str(), align, entrySize,
	    linkedSection.c_str(), infoSection.c_str(), infoData);
}


void BinaryView::RemoveUserSection(const string& name)
{
	BNRemoveUserSection(m_object, name.c_str());
}


vector<Ref<Section>> BinaryView::GetSections()
{
	size_t count;
	BNSection** sections = BNGetSections(m_object, &count);

	vector<Ref<Section>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new Section(BNNewSectionReference(sections[i])));

	BNFreeSectionList(sections, count);
	return result;
}


vector<Ref<Section>> BinaryView::GetSectionsAt(uint64_t addr)
{
	size_t count;
	BNSection** sections = BNGetSectionsAt(m_object, addr, &count);

	vector<Ref<Section>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(new Section(BNNewSectionReference(sections[i])));
	}

	BNFreeSectionList(sections, count);
	return result;
}


Ref<Section> BinaryView::GetSectionByName(const string& name)
{
	BNSection* section = BNGetSectionByName(m_object, name.c_str());
	if (section)
		return new Section(BNNewSectionReference(section));
	return nullptr;
}


vector<string> BinaryView::GetUniqueSectionNames(const vector<string>& names)
{
	const char** incomingNames = new const char*[names.size()];
	for (size_t i = 0; i < names.size(); i++)
		incomingNames[i] = names[i].c_str();

	char** outgoingNames = BNGetUniqueSectionNames(m_object, incomingNames, names.size());
	vector<string> result;
	result.reserve(names.size());
	for (size_t i = 0; i < names.size(); i++)
		result.push_back(outgoingNames[i]);

	BNFreeStringList(outgoingNames, names.size());
	return result;
}


string BinaryView::GetCommentForAddress(uint64_t addr) const
{
	char* comment = BNGetGlobalCommentForAddress(m_object, addr);
	string result = comment;
	BNFreeString(comment);
	return result;
}


vector<uint64_t> BinaryView::GetCommentedAddresses() const
{
	size_t count;
	uint64_t* addrs = BNGetGlobalCommentedAddresses(m_object, &count);
	vector<uint64_t> result;
	result.insert(result.end(), addrs, &addrs[count]);
	BNFreeAddressList(addrs);
	return result;
}


void BinaryView::SetCommentForAddress(uint64_t addr, const string& comment)
{
	BNSetGlobalCommentForAddress(m_object, addr, comment.c_str());
}


vector<BNAddressRange> BinaryView::GetAllocatedRanges()
{
	size_t count;
	BNAddressRange* ranges = BNGetAllocatedRanges(m_object, &count);

	vector<BNAddressRange> result;
	copy(&ranges[0], &ranges[count], back_inserter(result));
	BNFreeAddressRanges(ranges);
	return result;
}


void BinaryView::StoreMetadata(const std::string& key, Ref<Metadata> inValue, bool isAuto)
{
	if (!inValue)
		return;
	BNBinaryViewStoreMetadata(m_object, key.c_str(), inValue->GetObject(), isAuto);
}


Ref<Metadata> BinaryView::QueryMetadata(const std::string& key)
{
	BNMetadata* value = BNBinaryViewQueryMetadata(m_object, key.c_str());
	if (!value)
		return nullptr;
	return new Metadata(value);
}


void BinaryView::RemoveMetadata(const std::string& key)
{
	BNBinaryViewRemoveMetadata(m_object, key.c_str());
}


string BinaryView::GetStringMetadata(const string& key)
{
	auto data = QueryMetadata(key);
	if (!data || !data->IsString())
		throw QueryMetadataException("Failed to find key: " + key);
	return data->GetString();
}


vector<uint8_t> BinaryView::GetRawMetadata(const string& key)
{
	auto data = QueryMetadata(key);
	if (!data || !data->IsRaw())
		throw QueryMetadataException("Failed to find key: " + key);
	return data->GetRaw();
}


uint64_t BinaryView::GetUIntMetadata(const string& key)
{
	auto data = QueryMetadata(key);
	if (!data || !data->IsUnsignedInteger())
		throw QueryMetadataException("Failed to find key: " + key);
	return data->GetUnsignedInteger();
}


vector<string> BinaryView::GetLoadSettingsTypeNames()
{
	size_t count = 0;
	char** outgoingNames = BNBinaryViewGetLoadSettingsTypeNames(m_object, &count);
	vector<string> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(outgoingNames[i]);

	BNFreeStringList(outgoingNames, count);
	return result;
}


Ref<Settings> BinaryView::GetLoadSettings(const string& typeName)
{
	BNSettings* settings = BNBinaryViewGetLoadSettings(m_object, typeName.c_str());
	if (!settings)
		return nullptr;
	return new Settings(settings);
}


void BinaryView::SetLoadSettings(const string& typeName, Ref<Settings> settings)
{
	BNBinaryViewSetLoadSettings(m_object, typeName.c_str(), settings ? settings->GetObject() : nullptr);
}


BNAnalysisParameters BinaryView::GetParametersForAnalysis()
{
	return BNGetParametersForAnalysis(m_object);
}


void BinaryView::SetParametersForAnalysis(BNAnalysisParameters params)
{
	BNSetParametersForAnalysis(m_object, params);
}


uint64_t BinaryView::GetMaxFunctionSizeForAnalysis()
{
	return BNGetMaxFunctionSizeForAnalysis(m_object);
}


void BinaryView::SetMaxFunctionSizeForAnalysis(uint64_t size)
{
	BNSetMaxFunctionSizeForAnalysis(m_object, size);
}


bool BinaryView::GetNewAutoFunctionAnalysisSuppressed()
{
	return BNGetNewAutoFunctionAnalysisSuppressed(m_object);
}


void BinaryView::SetNewAutoFunctionAnalysisSuppressed(bool suppress)
{
	BNSetNewAutoFunctionAnalysisSuppressed(m_object, suppress);
}


set<NameSpace> BinaryView::GetNameSpaces() const
{
	set<NameSpace> nameSpaces;
	size_t count = 0;
	BNNameSpace* nameSpaceList = BNGetNameSpaces(m_object, &count);
	for (size_t i = 0; i < count; i++)
		nameSpaces.insert(NameSpace::FromAPIObject(&nameSpaceList[i]));
	BNFreeNameSpaceList(nameSpaceList, count);
	return nameSpaces;
}


NameSpace BinaryView::GetInternalNameSpace()
{
	BNNameSpace ns = BNGetInternalNameSpace();
	NameSpace nameSpace = NameSpace::FromAPIObject(&ns);
	BNFreeNameSpace(&ns);
	return nameSpace;
}


NameSpace BinaryView::GetExternalNameSpace()
{
	BNNameSpace ns = BNGetExternalNameSpace();
	NameSpace nameSpace = NameSpace::FromAPIObject(&ns);
	BNFreeNameSpace(&ns);
	return nameSpace;
}


bool BinaryView::ParseExpression(
    Ref<BinaryView> view, const string& expression, uint64_t& offset, uint64_t here, string& errorString)
{
	char* err = nullptr;
	if (!BNParseExpression(view ? view->GetObject() : nullptr, expression.c_str(), &offset, here, &err))
	{
		if (err)
		{
			errorString = string(err);
			BNFreeParseError(err);
		}
		return false;
	}
	return true;
}


Ref<Structure> BinaryView::CreateStructureFromOffsetAccess(const QualifiedName& type, bool* newMemberAdded) const
{
	BNQualifiedName typeObj = type.GetAPIObject();
	BNStructure* result = BNCreateStructureFromOffsetAccess(m_object, &typeObj, newMemberAdded);
	return new Structure(result);
}


Confidence<Ref<Type>> BinaryView::CreateStructureMemberFromAccess(const QualifiedName& name, uint64_t offset) const
{
	BNQualifiedName typeObj = name.GetAPIObject();
	BNTypeWithConfidence type = BNCreateStructureMemberFromAccess(m_object, &typeObj, offset);

	if (type.type)
		return Confidence<Ref<Type>>(new Type(BNNewTypeReference(type.type)), type.confidence);
	return nullptr;
}


Ref<Logger> BinaryView::CreateLogger(const string& name)
{
	return LogRegistry::CreateLogger(name, GetFile()->GetSessionId());
}


Relocation::Relocation(BNRelocation* reloc)
{
	m_object = reloc;
}


BNRelocationInfo Relocation::GetInfo() const
{
	return BNRelocationGetInfo(m_object);
}


Architecture* Relocation::GetArchitecture() const
{
	return new CoreArchitecture(BNRelocationGetArchitecture(m_object));
}


uint64_t Relocation::GetTarget() const
{
	return BNRelocationGetTarget(m_object);
}


uint64_t Relocation::GetAddress() const
{
	return BNRelocationGetReloc(m_object);
}


Ref<Symbol> Relocation::GetSymbol() const
{
	BNSymbol* sym = BNRelocationGetSymbol(m_object);
	if (!sym)
		return nullptr;
	return new Symbol(sym);
}


BinaryData::BinaryData(FileMetadata* file) : BinaryView(BNCreateBinaryDataView(file->GetObject())) {}


BinaryData::BinaryData(FileMetadata* file, const DataBuffer& data) :
    BinaryView(BNCreateBinaryDataViewFromBuffer(file->GetObject(), data.GetBufferObject()))
{}


BinaryData::BinaryData(FileMetadata* file, const void* data, size_t len) :
    BinaryView(BNCreateBinaryDataViewFromData(file->GetObject(), data, len))
{}


BinaryData::BinaryData(FileMetadata* file, const string& path) :
    BinaryView(BNCreateBinaryDataViewFromFilename(file->GetObject(), path.c_str()))
{}


BinaryData::BinaryData(FileMetadata* file, FileAccessor* accessor) :
    BinaryView(BNCreateBinaryDataViewFromFile(file->GetObject(), accessor->GetCallbacks()))
{}


Ref<BinaryView> BinaryNinja::OpenView(const std::string& filename, bool updateAnalysis, std::function<bool(size_t, size_t)> progress, Json::Value options)
{
	if (!progress)
		progress = [](size_t, size_t) { return true; };

	// Loading will surely fail if the file does not exist, so exit early
	if (!BNPathExists(filename.c_str()))
		return nullptr;

	// Detect bndb
	bool isDatabase = false;
	Ref<BinaryView> view = nullptr;

	if (filename.size() > 6 && filename.substr(filename.size() - 5) == ".bndb")
	{
		// Open database, read raw view contents from it
		static const std::string sqlite_header = "SQLite format 3";

		FILE* f = fopen(filename.c_str(), "rb");
		// Unable to open file
		if (f == nullptr)
			return nullptr;

		char header[0x20];
		fread(header, 1, sqlite_header.size(), f);
		fclose(f);
		header[sqlite_header.size()] = 0;

		// File is not a valid sqlite db
		if (sqlite_header != header)
			return nullptr;

		Ref<FileMetadata> file = new FileMetadata(filename);
		view = file->OpenDatabaseForConfiguration(filename);
		isDatabase = true;
	}
	else
	{
		// Open file, read raw contents
		Ref<FileMetadata> file = new FileMetadata(filename);
		view = new BinaryData(file, filename);
	}

	if (!view)
		return nullptr;
	return OpenView(view, updateAnalysis, progress, options, isDatabase);
}


Ref<BinaryView> BinaryNinja::OpenView(const DataBuffer& rawData, bool updateAnalysis, std::function<bool(size_t, size_t)> progress, Json::Value options)
{
	Ref<FileMetadata> file = new FileMetadata();
	Ref<BinaryView> view = new BinaryData(file, rawData);
	return OpenView(view, updateAnalysis, progress, options, false);
}


Ref<BinaryView> BinaryNinja::OpenView(Ref<BinaryView> view, bool updateAnalysis, std::function<bool(size_t, size_t)> progress, Json::Value options, bool isDatabase)
{
	Ref<BinaryViewType> bvt;
	Ref<BinaryViewType> universalBvt;
	for (auto available : BinaryViewType::GetViewTypesForData(view))
	{
		if (available->GetName() == "Universal")
		{
			universalBvt = available;
			continue;
		}
		if (!bvt && available->GetName() != "Raw")
		{
			bvt = available;
		}
	}

	// No available views: Load as Mapped
	if (!bvt)
		bvt = BinaryViewType::GetByName("Mapped");

	Ref<Settings> defaultSettings = Settings::Instance(bvt->GetName() + "_settings");
	defaultSettings->DeserializeSchema(Settings::Instance()->SerializeSchema());
	defaultSettings->SetResourceId(bvt->GetName());

	Ref<Settings> loadSettings;
	if (isDatabase)
	{
		loadSettings = view->GetLoadSettings(bvt->GetName());
	}
	if (!loadSettings)
	{
		if (universalBvt && options.isMember("files.universal.architecturePreference"))
		{
			// Load universal architecture
			loadSettings = universalBvt->GetLoadSettingsForData(view);
			if (!loadSettings)
			{
				LogError("Could not load entry from Universal image. No load settings!");
				return nullptr;
			}
			std::string architectures = loadSettings->Get<std::string>("loader.universal.architectures");

			std::unique_ptr<Json::CharReader> reader(Json::CharReaderBuilder().newCharReader());
			Json::Value archList;
			std::string errors;
			if (!reader->parse((const char*)architectures.data(), (const char*)architectures.data() + architectures.size(), &archList, &errors))
			{
				BinaryNinja::LogError("Error parsing architecture list: %s", errors.data());
				return nullptr;
			}

			Json::Value archEntry;
			for (auto archPref : options["files.universal.architecturePreference"])
			{
				for (auto entry : archList)
				{
					if (entry["architecture"].asString() == archPref.asString())
					{
						archEntry = entry;
						break;
					}
				}
				if (!archEntry.isNull())
					break;
			}
			if (archEntry.isNull())
			{
				std::string error = "Could not load any of:";
				for (auto archPref : options["files.universal.architecturePreference"])
				{
					error += string(" ") + archPref.asString();
				}
				error += " from Universal image. Entry not found! Available entries:";
				for (auto entry : archList)
				{
					error += string(" ") + entry["architecture"].asString();
				}
				LogError("%s", error.c_str());
				return nullptr;
			}

			loadSettings = Settings::Instance(GetUniqueIdentifierString());

			Json::StreamWriterBuilder builder;
			builder["indentation"] = "";
			string json = Json::writeString(builder, archEntry["loadSchema"]);

			loadSettings->DeserializeSchema(json);
		}
		else
		{
			// Load non-universal architecture
			loadSettings = bvt->GetLoadSettingsForData(view);
		}
	}

	if (!loadSettings)
	{
		LogError("Could not get load settings for binary view of type '%s'", bvt->GetName().c_str());
		return nullptr;
	}

	loadSettings->SetResourceId(bvt->GetName());
	view->SetLoadSettings(bvt->GetName(), loadSettings);

	for (auto key : options.getMemberNames())
	{
		auto value = options[key];
		if (loadSettings->Contains(key))
		{
			Json::StreamWriterBuilder builder;
			builder["indentation"] = "";
			string json = Json::writeString(builder, value);

			if (!loadSettings->SetJson(key, json, view))
			{
				LogError("Setting: %s set operation failed!", key.c_str());
				return nullptr;
			}
		}
		else if (defaultSettings->Contains(key))
		{
			Json::StreamWriterBuilder builder;
			builder["indentation"] = "";
			string json = Json::writeString(builder, value);

			if (!defaultSettings->SetJson(key, json, view))
			{
				LogError("Setting: %s set operation failed!", key.c_str());
				return nullptr;
			}
		}
		else
		{
			LogError("Setting: %s not available!", key.c_str());
			return nullptr;
		}
	}

	Ref<BinaryView> bv;
	if (isDatabase)
	{
		view = view->GetFile()->OpenExistingDatabase(view->GetFile()->GetFilename(), progress);
		if (!view)
		{
			LogError("Unable to open existing database with filename %s", view->GetFile()->GetFilename().c_str());
			return nullptr;
		}
		bv = view->GetFile()->GetViewOfType(bvt->GetName());
	}
	else
	{
		bv = bvt->Create(view);
	}

	if (!bv)
	{
		return view;
	}
	if (updateAnalysis)
	{
		bv->UpdateAnalysisAndWait();
	}
	return bv;
}

