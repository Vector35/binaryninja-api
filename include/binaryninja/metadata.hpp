#pragma once
#include <string>
#include <vector>
#include <map>
#include "binaryninjacore/metadata.h"
#include "refcount.hpp"

namespace BinaryNinja {
	typedef BNMetadataType MetadataType;

	class Metadata : public CoreRefCountObject<BNMetadata, BNNewMetadataReference, BNFreeMetadata>
	{
	  public:
		explicit Metadata(BNMetadata* structuredData);
		explicit Metadata(bool data);
		explicit Metadata(const std::string& data);
		explicit Metadata(uint64_t data);
		explicit Metadata(int64_t data);
		explicit Metadata(double data);
		explicit Metadata(const std::vector<bool>& data);
		explicit Metadata(const std::vector<std::string>& data);
		explicit Metadata(const std::vector<uint64_t>& data);
		explicit Metadata(const std::vector<int64_t>& data);
		explicit Metadata(const std::vector<double>& data);
		explicit Metadata(const std::vector<uint8_t>& data);
		explicit Metadata(const std::vector<Ref<Metadata>>& data);
		explicit Metadata(const std::map<std::string, Ref<Metadata>>& data);
		explicit Metadata(MetadataType type);
		virtual ~Metadata() {}

		bool operator==(const Metadata& rhs);
		Ref<Metadata> operator[](const std::string& key);
		Ref<Metadata> operator[](size_t idx);

		MetadataType GetType() const;
		bool GetBoolean() const;
		std::string GetString() const;
		uint64_t GetUnsignedInteger() const;
		int64_t GetSignedInteger() const;
		double GetDouble() const;
		std::vector<bool> GetBooleanList() const;
		std::vector<std::string> GetStringList() const;
		std::vector<uint64_t> GetUnsignedIntegerList() const;
		std::vector<int64_t> GetSignedIntegerList() const;
		std::vector<double> GetDoubleList() const;
		std::vector<uint8_t> GetRaw() const;
		std::vector<Ref<Metadata>> GetArray();
		std::map<std::string, Ref<Metadata>> GetKeyValueStore();

		// For key-value data only
		Ref<Metadata> Get(const std::string& key);
		bool SetValueForKey(const std::string& key, Ref<Metadata> data);
		void RemoveKey(const std::string& key);

		// For array data only
		Ref<Metadata> Get(size_t index);
		bool Append(Ref<Metadata> data);
		void RemoveIndex(size_t index);
		size_t Size() const;

		bool IsBoolean() const;
		bool IsString() const;
		bool IsUnsignedInteger() const;
		bool IsSignedInteger() const;
		bool IsDouble() const;
		bool IsBooleanList() const;
		bool IsStringList() const;
		bool IsUnsignedIntegerList() const;
		bool IsSignedIntegerList() const;
		bool IsDoubleList() const;
		bool IsRaw() const;
		bool IsArray() const;
		bool IsKeyValueStore() const;
	};

}