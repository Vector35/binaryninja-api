#pragma once

#include <map>
#include <string>
#include <vector>
#include "binaryninjacore.h"
#include "refcount.h"

namespace BinaryNinja
{
	typedef BNMetadataType MetadataType;

	/*!
	    \ingroup metadata
	*/
	class Metadata : public CoreRefCountObject<BNMetadata, BNNewMetadataReference, BNFreeMetadata>
	{
	public:
		explicit Metadata(BNMetadata* structuredData);
		/*! Create a new Metadata object representing a bool

		    @threadsafe

		    \param data Bool to store

		*/
		explicit Metadata(bool data);

		/*! Create a new Metadata object representing a string

		    @threadsafe

		    \param data string to store

		*/
		explicit Metadata(const std::string& data);

		/*! Create a new Metadata object representing a uint64

		    @threadsafe

		    \param data - uint64 to store

		*/
		explicit Metadata(uint64_t data);

		/*! Create a new Metadata object representing an int64

		    @threadsafe

		    \param data - int64 to store

		*/
		explicit Metadata(int64_t data);

		/*! Create a new Metadata object representing a double

		    @threadsafe

		    \param data - double to store

		*/
		explicit Metadata(double data);

		/*! Create a new Metadata object representing a vector of bools

		    @threadsafe

		    \param data - list of bools to store

		*/
		explicit Metadata(const std::vector<bool>& data);

		/*! Create a new Metadata object representing a vector of strings

		    @threadsafe

		    \param data - list of strings to store

		*/
		explicit Metadata(const std::vector<std::string>& data);

		/*! Create a new Metadata object representing a vector of uint64s

		    @threadsafe

		    \param data - list of uint64s to store

		*/
		explicit Metadata(const std::vector<uint64_t>& data);

		/*! Create a new Metadata object representing a vector of int64s

		    @threadsafe

		    \param data - list of int64s to store

		*/
		explicit Metadata(const std::vector<int64_t>& data);

		/*! Create a new Metadata object representing a vector of doubles

		    @threadsafe

		    \param data - list of doubles to store

		*/
		explicit Metadata(const std::vector<double>& data);

		/*! Create a new Metadata object representing a vector of bytes to store

		    @threadsafe

		    \param data - list of bytes to store

		*/
		explicit Metadata(const std::vector<uint8_t>& data);

		/*! Create a new Metadata object representing a vector of children Metadata objects

		    @threadsafe

		    \param data - list of Metadata objects to store

		*/
		explicit Metadata(const std::vector<Ref<Metadata>>& data);

		/*! Create a new Metadata object representing a map of strings to metadata objects

		    @threadsafe

		    \param data - map of strings to metadata objects

		*/
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
		std::vector<Ref<Metadata>> GetArray() const;
		std::map<std::string, Ref<Metadata>> GetKeyValueStore() const;
		std::string GetJsonString() const;

		// For key-value data only
		/*! Get a Metadata object by key. Only for if IsKeyValueStore == true

			@threadunsafewith{SetValueForKey and RemoveKey}

		    \param key
		    \return
		 */
		Ref<Metadata> Get(const std::string& key);
		/*! Set the value mapped to by a particular string. Only for if IsKeyValueStore == true

			@threadunsafewith{Get and RemoveKey}

		    \param key
		    \param data
		    \return
		 */
		bool SetValueForKey(const std::string& key, Ref<Metadata> data);

		/*! Remove a key from the map. Only for if IsKeyValueStore == true

			@threadunsafewith{SetValueForKey and Get}

		    \param key - Key to remove
		 */
		void RemoveKey(const std::string& key);

		// For array data only
		/*! Get an item at a given index

		    For array data only

			@threadunsafewith{Array data modifiers}

		    \param index Index of the item to retrieve
		    \return Item at that index, if valid.
		 */
		Ref<Metadata> Get(size_t index);

		/*! Append an item to the array

		    For array data only

			@threadunsafewith{Array data modifiers}

		    \param data Data to append
		    \return Whether the append was successful
		 */
		bool Append(Ref<Metadata> data);

		/*! Remove an item at a given index

		    For array data only

			@threadunsafewith{Array data modifiers}

		    \param index Index of the item to remove
		 */
		void RemoveIndex(size_t index);

		/*! Get the size of the array

		    For array data only

			@threadunsafewith{Array data modifiers}

		    \return Size of the array
		 */
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
