
#pragma once
#include <string>
#include "binaryninjacore/databuffer.h"

namespace BinaryNinja {

	class DataBuffer
	{
		BNDataBuffer* m_buffer;

	  public:
		DataBuffer();
		DataBuffer(size_t len);
		DataBuffer(const void* data, size_t len);
		DataBuffer(const DataBuffer& buf);
		DataBuffer(DataBuffer&& buf);
		DataBuffer(BNDataBuffer* buf);
		~DataBuffer();

		DataBuffer& operator=(const DataBuffer& buf);
		DataBuffer& operator=(DataBuffer&& buf);

		BNDataBuffer* GetBufferObject() const { return m_buffer; }

		void* GetData();
		const void* GetData() const;
		void* GetDataAt(size_t offset);
		const void* GetDataAt(size_t offset) const;
		size_t GetLength() const;

		void SetSize(size_t len);
		void Clear();
		void Append(const void* data, size_t len);
		void Append(const DataBuffer& buf);
		void AppendByte(uint8_t val);

		DataBuffer GetSlice(size_t start, size_t len);

		uint8_t& operator[](size_t offset);
		const uint8_t& operator[](size_t offset) const;

		bool operator==(const DataBuffer& other) const;
		bool operator!=(const DataBuffer& other) const;

		std::string ToEscapedString() const;
		static DataBuffer FromEscapedString(const std::string& src);
		std::string ToBase64() const;
		static DataBuffer FromBase64(const std::string& src);

		bool ZlibCompress(DataBuffer& output) const;
		bool ZlibDecompress(DataBuffer& output) const;
	};

	std::string EscapeString(const std::string& s);
	std::string UnescapeString(const std::string& s);
}