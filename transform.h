#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <map>
#include <string>
#include <vector>

namespace BinaryNinja
{
	class DataBuffer;

	/*!
		\ingroup transform
	*/
	struct TransformParameter
	{
		std::string name, longName;
		size_t fixedLength;  // Variable length if zero
	};

	/*! Allows users to implement custom transformations.

	    New transformations may be added at runtime, so an instance of a transform is created like

		\code{.cpp}

	 	DataBuffer inputData = binaryView->ReadBuffer(0, 32); // Read the first 32 bytes of the file
	 	DataBuffer outputDataHash;

		Transform::GetByName("SHA512")->Encode(inputData, outputDataHash); // Writes the SHA512 hash to outputDataHash

		\endcode

	 	Getting a list of registered transforms:

	 	<b> From the interactive python console: </b>
	 	\code{.py}
	 	list(Transform)
	 	\endcode

	 	<b> At Runtime: </b>
	 	\code{.cpp}
	    std::vector<Ref<Transform>> registeredTypes = Transform::GetTransformTypes();
	 	\endcode

		\ingroup transform
	*/
	class Transform : public StaticCoreRefCountObject<BNTransform>
	{
	  protected:
		BNTransformType m_typeForRegister;
		std::string m_nameForRegister, m_longNameForRegister, m_groupForRegister;

		Transform(BNTransform* xform);

		static BNTransformParameterInfo* GetParametersCallback(void* ctxt, size_t* count);
		static void FreeParametersCallback(BNTransformParameterInfo* params, size_t count);
		static bool DecodeCallback(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);
		static bool EncodeCallback(
		    void* ctxt, BNDataBuffer* input, BNDataBuffer* output, BNTransformParameter* params, size_t paramCount);

		static std::vector<TransformParameter> EncryptionKeyParameters(size_t fixedKeyLength = 0);
		static std::vector<TransformParameter> EncryptionKeyAndIVParameters(
		    size_t fixedKeyLength = 0, size_t fixedIVLength = 0);

	  public:
		Transform(BNTransformType type, const std::string& name, const std::string& longName, const std::string& group);

		static void Register(Transform* xform);
		static Ref<Transform> GetByName(const std::string& name);
		static std::vector<Ref<Transform>> GetTransformTypes();

		BNTransformType GetType() const;
		std::string GetName() const;
		std::string GetLongName() const;
		std::string GetGroup() const;

		virtual std::vector<TransformParameter> GetParameters() const;

		virtual bool Decode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>());
		virtual bool Encode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>());
	};

	/*!
		\ingroup transform
	*/
	class CoreTransform : public Transform
	{
	  public:
		CoreTransform(BNTransform* xform);
		virtual std::vector<TransformParameter> GetParameters() const override;

		virtual bool Decode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>()) override;
		virtual bool Encode(const DataBuffer& input, DataBuffer& output,
		    const std::map<std::string, DataBuffer>& params = std::map<std::string, DataBuffer>()) override;
	};

}
