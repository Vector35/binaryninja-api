#pragma once

#include "binaryninjacore.h"
#include <cstdint>
#include <string>


namespace BinaryNinja
{
	/*!
		\ingroup databuffer
	*/
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

		/*! Get the raw pointer to the data contained within this buffer

			@threadunsafe
		*/
		void* GetData();

		/*! Get the raw pointer to the data contained within this buffer, as a const pointer.

			@threadunsafe
		*/
		const void* GetData() const;

		/*! Get the raw pointer to the data contained within this buffer, starting at a given offset

			@threadunsafe
		*/
		void* GetDataAt(size_t offset);

		/*! Get the const raw pointer to the data contained within this buffer, starting at a given offset

			@threadunsafe
		*/
		const void* GetDataAt(size_t offset) const;

		/*! Get the length of the data contained within this buffer

			@threadunsafe
		*/
		size_t GetLength() const;

		/*! Set the size of the data pointed to by this buffer

			@threadunsafe
		*/
		void SetSize(size_t len);

		/*! Clear the data contained by this buffer.

			\note This will call \c free() on this buffer's data pointer. You shouldn't call it yourself, typically ever.

			@threadunsafe
		*/
		void Clear();

		/*! Append \c len contents of the pointer \c data to the end of the buffer

			\note This will typically call \c realloc() on this buffer's data pointer. You should hold this DataBuffer and use it for accesses, instead of storing the raw pointer.

			@threadunsafe
		*/
		void Append(const void* data, size_t len);

		/*! Append the contents of databuffer \c buf to the current DataBuffer

			\note This will typically call \c realloc() on this buffer's data pointer. You should hold this DataBuffer and use it for accesses, instead of storing the raw pointer.

			@threadunsafe
		*/
		void Append(const DataBuffer& buf);

		/*! Append a single byte

			\note This will typically call \c realloc() on this buffer's data pointer. You should hold this DataBuffer and use it for accesses, instead of storing the raw pointer.

			@threadunsafe
		*/
		void AppendByte(uint8_t val);


		/*! Get the contents of a given slice of data, as a DataBuffer

			@threadunsafe
		*/
		DataBuffer GetSlice(size_t start, size_t len);

		uint8_t& operator[](size_t offset);
		const uint8_t& operator[](size_t offset) const;

		bool operator==(const DataBuffer& other) const;
		bool operator!=(const DataBuffer& other) const;

		/*! Convert the contents of the DataBuffer to a string

			\param nullTerminates Whether the decoder should stop and return the string after encountering a null (\x00) byte.

			@threadunsafe
		*/
		std::string ToEscapedString(bool nullTerminates = false) const;

		/*! Create a DataBuffer from a given escaped string.

			\param src Input string
			\returns Databuffer created from this string
		*/
		static DataBuffer FromEscapedString(const std::string& src);

		/*! Convert the contents of this DataBuffer to a base64 representation

			@threadunsafe
		*/
		std::string ToBase64() const;

		/*! Create a DataBuffer from a given base64 string.

			\param src Input base64 string
			\returns Databuffer created from this string
		*/
		static DataBuffer FromBase64(const std::string& src);

		/*! Compress this databuffer via ZLIB compression

			@threadunsafe

			\param[out] output Output DataBuffer the compressed contents will be stored in.
			\returns Whether compression was successful
		*/
		bool ZlibCompress(DataBuffer& output) const;

		/*! Decompress the contents of this buffer via ZLIB compression

			@threadunsafe

			\param[out] output Output DataBuffer the decompressed contents will be stored in.
			\returns Whether decompression was successful
		*/
		bool ZlibDecompress(DataBuffer& output) const;

		/*! Decompress the contents of this buffer via LZMA compression

		    @threadunsafe

		    \param[out] output Output DataBuffer the decompressed contents will be stored in.
		    \returns Whether decompression was successful
		*/
		bool LzmaDecompress(DataBuffer& output) const;

		/*! Decompress the contents of this buffer via LZMA2 compression

		    @threadunsafe

		    \param[out] output Output DataBuffer the decompressed contents will be stored in.
		    \returns Whether decompression was successful
		*/
		bool Lzma2Decompress(DataBuffer& output) const;

		/*! Decompress the contents of this buffer via XZ compression

		    @threadunsafe

		    \param[out] output Output DataBuffer the decompressed contents will be stored in.
		    \returns Whether decompression was successful
		*/
		bool XzDecompress(DataBuffer& output) const;
	};

}
