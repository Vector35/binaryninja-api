//
// Created by kat on 5/31/23.
//

/*
 * Welcome to, this file.
 *
 * This is a metadata serialization helper.
 *
 * Have you ever wished turning a complex datastructure into a Metadata object was as easy in C++ as it is in python?
 * Do you like macros and templates?
 *
 * Great news.
 *
 * Implement these on your `public MetadataSerializable<T>` subclass:
 * ```
    class MyClass : public MetadataSerializable<MyClass> {
		void Store(SerializationContext& context) const {
			MSS(m_someVariable);
			MSS(m_someOtherVariable);
		}
		void Load(DeserializationContext& context) {
			MSL(m_someVariable);
			MSL(m_someOtherVariable);
		}
	}
 ```
 * Then, you can turn your object into a Metadata object with `AsMetadata()`, and load it back with
 `LoadFromMetadata()`.
 *
 * Serialized fields will be automatically repopulated.
 *
 * Other ser/deser formats (rapidjson objects, strings) also exist. You can use these to achieve nesting, but probably
 avoid that.
 * */

#ifndef SHAREDCACHE_CORE_METADATASERIALIZABLE_HPP
#define SHAREDCACHE_CORE_METADATASERIALIZABLE_HPP

#include <cassert>
#include "binaryninjaapi.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"
#include "../api/sharedcachecore.h"
#include "view/macho/machoview.h"

using namespace BinaryNinja;

namespace SharedCacheCore {

#define MSS(name)						 context.store(#name, name)
#define MSS_CAST(name, type)			 context.store(#name, (type) name)
#define MSS_SUBCLASS(name)		 		 Serialize(context, #name, name)
#define MSL(name)						 name = context.load<decltype(name)>(#name)
#define MSL_CAST(name, storedType, type) name = (type)context.load<storedType>(#name)

struct DeserializationContext;

struct SerializationContext {
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer;

	SerializationContext() : buffer(), writer(buffer) {
	}

	template <typename T>
	void store(std::string_view x, const T& y)
	{
		Serialize(*this, x, y);
	}
};

struct DeserializationContext {
	rapidjson::Document doc;

	template <typename T>
	T load(std::string_view x)
	{
		T value;
		Deserialize(*this, x, value);
		return value;
	}
};

template <typename Derived, typename LoadResult = Derived>
class MetadataSerializable {
public:
	template <typename... Args>
	std::string AsString(Args&&... args) const {
		SerializationContext context;
		Store(context, std::forward<Args>(args)...);

		return context.buffer.GetString();
	}

	static LoadResult LoadFromString(const std::string& s) {
		DeserializationContext context;
		[[maybe_unused]] rapidjson::ParseResult result = context.doc.Parse(s.c_str());
		assert(result);
		return Derived::Load(context);
	}

	static LoadResult LoadFromValue(rapidjson::Value& s) {
		DeserializationContext context;
		context.doc.CopyFrom(s, context.doc.GetAllocator());
		return Derived::Load(context);
	}

	template <typename... Args>
	Ref<Metadata> AsMetadata(Args&&... args) const {
		return new Metadata(AsString(std::forward<Args>(args)...));
	}

	template <typename... Args>
	void Store(SerializationContext& context, Args&&... args) const {
		context.writer.StartObject();
		AsDerived().Store(context, std::forward<Args>(args)...);
		context.writer.EndObject();
	}

private:
	const Derived& AsDerived() const { return static_cast<const Derived&>(*this); }
	Derived& AsDerived() { return static_cast<Derived&>(*this); }
};

// The functions below are not part of the FFI API, but are exported so they can be shared with sharedcacheui.

SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, std::string_view str);

template <typename T>
inline void Serialize(SerializationContext& context, const MetadataSerializable<T>& value)
{
	value.Store(context);
}

template <typename T>
inline void Serialize(SerializationContext& context, std::string_view name, const T& value)
{
	Serialize(context, name);
	Serialize(context, value);
}

template <typename First, typename Second>
void Serialize(SerializationContext& context, const std::pair<First, Second>& value)
{
	context.writer.StartArray();
	Serialize(context, value.first);
	Serialize(context, value.second);
	context.writer.EndArray();
}

template <typename K, typename V, typename L>
void Serialize(SerializationContext& context, const std::map<K, V, L>& value)
{
	context.writer.StartArray();
	for (auto& pair : value)
	{
		Serialize(context, pair);
	}
	context.writer.EndArray();
}

template <typename K, typename V>
void Serialize(SerializationContext& context, const std::unordered_map<K, V>& value)
{
	context.writer.StartArray();
	for (auto& pair : value)
	{
		Serialize(context, pair);
	}
	context.writer.EndArray();
}

template <typename T>
void Serialize(SerializationContext& context, const std::vector<T>& values)
{
	context.writer.StartArray();
	for (const auto& value : values)
	{
		Serialize(context, value);
	}
	context.writer.EndArray();
}

template <typename T>
void Serialize(SerializationContext& context, const std::optional<T>& value)
{
	if (value.has_value())
		Serialize(context, *value);
	else
		context.writer.Null();
}

SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, const char*);
SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, bool b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, bool& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, uint8_t b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, uint8_t& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, uint16_t b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, uint16_t& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, uint32_t b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, uint32_t& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, uint64_t b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, uint64_t& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, int8_t b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, int8_t& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, int16_t b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, int16_t& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, int32_t b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, int32_t& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, int64_t b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, int64_t& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, std::string_view b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext& context, const std::pair<uint64_t, std::pair<uint64_t, uint64_t>>& value);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::string& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::map<uint64_t, std::string>& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<uint64_t, std::string>& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<uint64_t, uint64_t>& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<std::string, std::unordered_map<uint64_t, uint64_t>>& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<std::string, std::string>& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::vector<std::string>& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::vector<std::pair<uint64_t, std::pair<uint64_t, uint64_t>>>& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::vector<std::pair<uint64_t, bool>>& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::vector<uint64_t>& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::unordered_map<std::string, uint64_t>& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext& context, std::string_view name, std::vector<std::pair<uint64_t, std::vector<std::pair<uint64_t, std::string>>>>& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext&, const mach_header_64& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, mach_header_64& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext&, const symtab_command& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, symtab_command& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext&, const dysymtab_command& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, dysymtab_command& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext&, const dyld_info_command& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, dyld_info_command& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext&, const routines_command_64& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, routines_command_64& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext&, const function_starts_command& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, function_starts_command& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext&, const section_64& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, std::vector<section_64>& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext&, const linkedit_data_command& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, linkedit_data_command& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext&, const segment_command_64& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, segment_command_64& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, std::vector<segment_command_64>& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext&, const build_version_command& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, build_version_command& b);
SHAREDCACHE_FFI_API void Serialize(SerializationContext&, const build_tool_version& b);
SHAREDCACHE_FFI_API void Deserialize(DeserializationContext&, std::string_view name, std::vector<build_tool_version>& b);

} // namespace SharedCacheCore

#endif	// SHAREDCACHE_METADATASERIALIZABLE_HPP
