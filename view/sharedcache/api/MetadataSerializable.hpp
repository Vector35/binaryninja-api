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
 * Implement these on your `public MetadataSerializable` subclass:
 * ```
	void Store() override {
		MSS(m_someVariable);
		MSS(m_someOtherVariable);
	}
	void Load() override {
		MSL(m_someVariable);
		MSL(m_someOtherVariable);
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

#include "binaryninjaapi.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"

#ifndef SHAREDCACHE_METADATASERIALIZABLE_HPP
#define SHAREDCACHE_METADATASERIALIZABLE_HPP

#define MSS(name)						 store(#name, name)
#define MSS_CAST(name, type)			 store(#name, (type) name)
#define MSS_SUBCLASS(name)		 		 Serialize(#name, name)
#define MSL(name)						 name = load(#name, name)
#define MSL_CAST(name, storedType, type) name = (type)load(#name, (storedType) name)
#define MSL_SUBCLASS(name)				 Deserialize(#name, name)

using namespace BinaryNinja;

class MetadataSerializable
{
protected:
	struct SerialContext
	{
		rapidjson::Document doc;
		rapidjson::Document::AllocatorType allocator;
	};
	struct DeserContext
	{
		rapidjson::Document doc;
	};

	DeserContext m_activeDeserContext;
	SerialContext m_activeContext;

public:
	MetadataSerializable()
	{
		m_activeContext.doc.SetObject();
		m_activeContext.allocator = m_activeContext.doc.GetAllocator();
	}

	// copy constructor
	MetadataSerializable(const MetadataSerializable& other)
	{
		m_activeContext.doc.CopyFrom(other.m_activeContext.doc, m_activeContext.doc.GetAllocator());
	}

	// copy assignment
	MetadataSerializable& operator=(const MetadataSerializable& other)
	{
		m_activeContext.doc.CopyFrom(other.m_activeContext.doc, m_activeContext.doc.GetAllocator());
		return *this;
	}

	virtual ~MetadataSerializable()
	{
	}

	void SetupSerContext(rapidjson::Document::AllocatorType* alloc = nullptr)
	{
		m_activeContext.doc.SetObject();
		m_activeContext.allocator = m_activeContext.doc.GetAllocator();
	}
	void S()
	{
		// fixme factor out
	}
	void Serialize(std::string& name, bool b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		m_activeContext.doc.AddMember(key, b, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, bool& b) { b = m_activeDeserContext.doc[name.c_str()].GetBool(); }

	void Serialize(std::string& name, uint8_t b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		m_activeContext.doc.AddMember(key, b, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, uint8_t& b)
	{
		b = static_cast<uint8_t>(m_activeDeserContext.doc[name.c_str()].GetUint64());
	}

	void Serialize(std::string& name, uint16_t b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		m_activeContext.doc.AddMember(key, b, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, uint16_t& b)
	{
		b = static_cast<uint16_t>(m_activeDeserContext.doc[name.c_str()].GetUint64());
	}

	void Serialize(std::string& name, uint32_t b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		m_activeContext.doc.AddMember(key, b, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, uint32_t& b)
	{
		b = static_cast<uint32_t>(m_activeDeserContext.doc[name.c_str()].GetUint64());
	}

	void Serialize(std::string& name, uint64_t b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		m_activeContext.doc.AddMember(key, b, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, uint64_t& b)
	{
		b = m_activeDeserContext.doc[name.c_str()].GetUint64();
	}

	void Serialize(std::string& name, int8_t b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		m_activeContext.doc.AddMember(key, b, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, int8_t& b)
	{
		b = m_activeDeserContext.doc[name.c_str()].GetInt64();
	}

	void Serialize(std::string& name, int16_t b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		m_activeContext.doc.AddMember(key, b, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, int16_t& b)
	{
		b = m_activeDeserContext.doc[name.c_str()].GetInt64();
	}

	void Serialize(std::string& name, int32_t b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		m_activeContext.doc.AddMember(key, b, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, int32_t& b)
	{
		b = m_activeDeserContext.doc[name.c_str()].GetInt();
	}

	void Serialize(std::string& name, int64_t b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		m_activeContext.doc.AddMember(key, b, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, int64_t& b)
	{
		b = m_activeDeserContext.doc[name.c_str()].GetInt64();
	}

	void Serialize(std::string& name, std::string b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		rapidjson::Value value(b.c_str(), m_activeContext.allocator);
		m_activeContext.doc.AddMember(key, value, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, std::string& b)
	{
		b = m_activeDeserContext.doc[name.c_str()].GetString();
	}

	void Serialize(std::string& name, std::map<uint64_t, std::string> b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		rapidjson::Value bArr(rapidjson::kArrayType);
		for (auto& i : b)
		{
			rapidjson::Value p(rapidjson::kArrayType);
			p.PushBack(i.first, m_activeContext.allocator);
			rapidjson::Value value(i.second.c_str(), m_activeContext.allocator);
			p.PushBack(value, m_activeContext.allocator);
			bArr.PushBack(p, m_activeContext.allocator);
		}
		m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, std::map<uint64_t, std::string>& b)
	{
		for (auto& i : m_activeDeserContext.doc[name.c_str()].GetArray())
			b[i.GetArray()[0].GetUint64()] = i.GetArray()[1].GetString();
	}

	void Serialize(std::string& name, std::unordered_map<uint64_t, std::string> b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		rapidjson::Value bArr(rapidjson::kArrayType);
		for (auto& i : b)
		{
			rapidjson::Value p(rapidjson::kArrayType);
			p.PushBack(i.first, m_activeContext.allocator);
			rapidjson::Value value(i.second.c_str(), m_activeContext.allocator);
			p.PushBack(value, m_activeContext.allocator);
			bArr.PushBack(p, m_activeContext.allocator);
		}
		m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
	}

	void Serialize(std::string& name, std::unordered_map<std::string, std::string> b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		rapidjson::Value bArr(rapidjson::kArrayType);
		for (auto& i : b)
		{
			rapidjson::Value p(rapidjson::kArrayType);
			rapidjson::Value key(i.first.c_str(), m_activeContext.allocator);
			rapidjson::Value value(i.second.c_str(), m_activeContext.allocator);
			p.PushBack(key, m_activeContext.allocator);
			p.PushBack(value, m_activeContext.allocator);
			bArr.PushBack(p, m_activeContext.allocator);
		}
		m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, std::unordered_map<uint64_t, std::string>& b)
	{
		for (auto& i : m_activeDeserContext.doc[name.c_str()].GetArray())
			b[i.GetArray()[0].GetUint64()] = i.GetArray()[1].GetString();
	}

	void Serialize(std::string& name, std::unordered_map<uint64_t, uint64_t> b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		rapidjson::Value bArr(rapidjson::kArrayType);
		for (auto& i : b)
		{
			rapidjson::Value p(rapidjson::kArrayType);
			p.PushBack(i.first, m_activeContext.allocator);
			p.PushBack(i.second, m_activeContext.allocator);
			bArr.PushBack(p, m_activeContext.allocator);
		}
		m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, std::unordered_map<uint64_t, uint64_t>& b)
	{
		for (auto& i : m_activeDeserContext.doc[name.c_str()].GetArray())
			b[i.GetArray()[0].GetUint64()] = i.GetArray()[1].GetUint64();
	}

	// std::unordered_map<std::string, std::unordered_map<uint64_t, uint64_t>>
	void Serialize(std::string& name, std::unordered_map<std::string, std::unordered_map<uint64_t, uint64_t>> b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		rapidjson::Value classes(rapidjson::kArrayType);
		for (auto& i : b)
		{
			rapidjson::Value classArr(rapidjson::kArrayType);
			rapidjson::Value classKey(i.first.c_str(), m_activeContext.allocator);
			classArr.PushBack(classKey, m_activeContext.allocator);
			rapidjson::Value membersArr(rapidjson::kArrayType);
			for (auto& j : i.second)
			{
				rapidjson::Value member(rapidjson::kArrayType);
				member.PushBack(j.first, m_activeContext.allocator);
				member.PushBack(j.second, m_activeContext.allocator);
				membersArr.PushBack(member, m_activeContext.allocator);
			}
			classArr.PushBack(membersArr, m_activeContext.allocator);
			classes.PushBack(classArr, m_activeContext.allocator);
		}
		m_activeContext.doc.AddMember(key, classes, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, std::unordered_map<std::string, std::unordered_map<uint64_t, uint64_t>>& b)
	{
		for (auto& i : m_activeDeserContext.doc[name.c_str()].GetArray())
		{
			std::string key = i.GetArray()[0].GetString();
			std::unordered_map<uint64_t, uint64_t> memArray;
			for (auto& member : i.GetArray()[1].GetArray())
			{
				memArray[member.GetArray()[0].GetUint64()] = member.GetArray()[1].GetUint64();
			}
			b[key] = memArray;
		}
	}

	void Deserialize(std::string& name, std::unordered_map<std::string, std::string>& b)
	{
		for (auto& i : m_activeDeserContext.doc[name.c_str()].GetArray())
			b[i.GetArray()[0].GetString()] = i.GetArray()[1].GetString();
	}

	void Serialize(std::string& name, std::vector<std::string> b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		rapidjson::Value bArr(rapidjson::kArrayType);
		for (const auto& s : b)
		{
			rapidjson::Value value(s.c_str(), m_activeContext.allocator);
			bArr.PushBack(value, m_activeContext.allocator);
		}
		m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, std::vector<std::string>& b)
	{
		for (auto& i : m_activeDeserContext.doc[name.c_str()].GetArray())
			b.emplace_back(i.GetString());
	}

	void Serialize(std::string& name, std::vector<std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		rapidjson::Value bArr(rapidjson::kArrayType);
		for (auto& i : b)
		{
			rapidjson::Value segV(rapidjson::kArrayType);
			segV.PushBack(i.first, m_activeContext.allocator);
			segV.PushBack(i.second.first, m_activeContext.allocator);
			segV.PushBack(i.second.second, m_activeContext.allocator);
			bArr.PushBack(segV, m_activeContext.allocator);
		}
		m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, std::vector<std::pair<uint64_t, std::pair<uint64_t, uint64_t>>>& b)
	{
		for (auto& i : m_activeDeserContext.doc[name.c_str()].GetArray())
		{
			std::pair<uint64_t, std::pair<uint64_t, uint64_t>> j;
			j.first = i.GetArray()[0].GetUint64();
			j.second.first = i.GetArray()[1].GetUint64();
			j.second.second = i.GetArray()[2].GetUint64();
			b.push_back(j);
		}
	}

	void Serialize(std::string& name, std::vector<std::pair<uint64_t, bool>> b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		rapidjson::Value bArr(rapidjson::kArrayType);
		for (auto& i : b)
		{
			rapidjson::Value segV(rapidjson::kArrayType);
			segV.PushBack(i.first, m_activeContext.allocator);
			segV.PushBack(i.second, m_activeContext.allocator);
			bArr.PushBack(segV, m_activeContext.allocator);
		}
		m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, std::vector<std::pair<uint64_t, bool>>& b)
	{
		for (auto& i : m_activeDeserContext.doc[name.c_str()].GetArray())
		{
			std::pair<uint64_t, bool> j;
			j.first = i.GetArray()[0].GetUint64();
			j.second = i.GetArray()[1].GetBool();
			b.push_back(j);
		}
	}

	void Serialize(std::string& name, std::vector<uint64_t> b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		rapidjson::Value bArr(rapidjson::kArrayType);
		for (auto& i : b)
		{
			bArr.PushBack(i, m_activeContext.allocator);
		}
		m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, std::vector<uint64_t>& b)
	{
		for (auto& i : m_activeDeserContext.doc[name.c_str()].GetArray())
		{
			b.push_back(i.GetUint64());
		}
	}

	// std::unordered_map<std::string, uint64_t>
	void Serialize(std::string& name, std::unordered_map<std::string, uint64_t> b)
	{
		S();
		rapidjson::Value key(name.c_str(), m_activeContext.allocator);
		rapidjson::Value bArr(rapidjson::kArrayType);
		for (auto& i : b)
		{
			rapidjson::Value p(rapidjson::kArrayType);
			rapidjson::Value key(i.first.c_str(), m_activeContext.allocator);
			p.PushBack(key, m_activeContext.allocator);
			p.PushBack(i.second, m_activeContext.allocator);
			bArr.PushBack(p, m_activeContext.allocator);
		}
		m_activeContext.doc.AddMember(key, bArr, m_activeContext.allocator);
	}
	void Deserialize(std::string& name, std::unordered_map<std::string, uint64_t>& b)
	{
		for (auto& i : m_activeDeserContext.doc[name.c_str()].GetArray())
		{
			b[i.GetArray()[0].GetString()] = i.GetArray()[1].GetUint64();
		}
	}

	template <typename T>
	void store(std::string x, T y)
	{
		Serialize(x, y);
	}

	template <typename T>
	T load(std::string x, T y)
	{
		T val;
		Deserialize(x, val);
		return val;
	}

	rapidjson::Document& GetDoc()
	{
		S();
		Store();
		return m_activeContext.doc;
	}

public:
	virtual void Store() = 0;
	virtual void Load() = 0;

	std::string AsString()
	{
		rapidjson::StringBuffer strbuf;
		rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(strbuf);
		GetDoc().Accept(writer);

		std::string s = strbuf.GetString();
		return s;
	}
	rapidjson::Document& AsDocument() { return GetDoc(); }
	void LoadFromString(const std::string& s)
	{
		m_activeDeserContext.doc.Parse(s.c_str());
		Load();
	}
	void LoadFromValue(rapidjson::Value& s)
	{
		m_activeDeserContext.doc.CopyFrom(s, m_activeDeserContext.doc.GetAllocator());
		Load();
	}
	Ref<Metadata> AsMetadata() { return new Metadata(AsString()); }
	bool LoadFromMetadata(const Ref<Metadata>& meta)
	{
		if (!meta->IsString())
			return false;
		LoadFromString(meta->GetString());
		return true;
	}
};

#endif	// SHAREDCACHE_METADATASERIALIZABLE_HPP
