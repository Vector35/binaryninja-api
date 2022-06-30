#pragma once
#include <string>
#include <vector>
#include "refcount.hpp"
#include "binaryninjacore/typeprinter.h"

namespace BinaryNinja {

	class TypePrinter: public StaticCoreRefCountObject<BNTypePrinter>
	{
		std::string m_nameForRegister;
	  protected:
		explicit TypePrinter(const std::string& name);
		TypePrinter(BNTypePrinter* printer);

		static bool GetTypeTokensCallback(void* ctxt, BNType* type, BNPlatform* platform,
			BNQualifiedName* name, uint8_t baseConfidence, BNTokenEscapingType escaping,
			BNInstructionTextToken** result, size_t* resultCount);
		static bool GetTypeTokensBeforeNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
			BNTokenEscapingType escaping, BNInstructionTextToken** result,
			size_t* resultCount);
		static bool GetTypeTokensAfterNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, uint8_t baseConfidence, BNType* parentType,
			BNTokenEscapingType escaping, BNInstructionTextToken** result,
			size_t* resultCount);
		static bool GetTypeStringCallback(void* ctxt, BNType* type, BNPlatform* platform,
			BNQualifiedName* name, BNTokenEscapingType escaping, char** result);
		static bool GetTypeStringBeforeNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, BNTokenEscapingType escaping, char** result);
		static bool GetTypeStringAfterNameCallback(void* ctxt, BNType* type,
			BNPlatform* platform, BNTokenEscapingType escaping, char** result);
		static bool GetTypeLinesCallback(void* ctxt, BNType* type, BNBinaryView* data,
			BNQualifiedName* name, int lineWidth, bool collapsed,
			BNTokenEscapingType escaping, BNTypeDefinitionLine** result, size_t* resultCount);
		static void FreeTokensCallback(void* ctxt, BNInstructionTextToken* tokens, size_t count);
		static void FreeStringCallback(void* ctxt, char* string);
		static void FreeLinesCallback(void* ctxt, BNTypeDefinitionLine* lines, size_t count);

	  public:
		static void Register(TypePrinter* printer);
		static std::vector<Ref<TypePrinter>> GetList();
		static Ref<TypePrinter> GetByName(const std::string& name);
		static Ref<TypePrinter> GetDefault();

		/*!
		    Generate a single-line text representation of a type
		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param name Name of the type
		    \param baseConfidence Confidence to use for tokens created for this type
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of text tokens representing the type
		 */
		virtual std::vector<InstructionTextToken> GetTypeTokens(
			Ref<Type> type,
			Ref<Platform> platform,
			const QualifiedName& name,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);
		/*!
		    In a single-line text representation of a type, generate the tokens that should
		    be printed before the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param baseConfidence Confidence to use for tokens created for this type
		    \param parentType Type of the parent of this type, or nullptr
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of text tokens representing the type
		 */
		virtual std::vector<InstructionTextToken> GetTypeTokensBeforeName(
			Ref<Type> type,
			Ref<Platform> platform,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			Ref<Type> parentType = nullptr,
			BNTokenEscapingType escaping = NoTokenEscapingType
		) = 0;
		/*!
		    In a single-line text representation of a type, generate the tokens that should
		    be printed after the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param baseConfidence Confidence to use for tokens created for this type
		    \param parentType Type of the parent of this type, or nullptr
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of text tokens representing the type
		 */
		virtual std::vector<InstructionTextToken> GetTypeTokensAfterName(
			Ref<Type> type,
			Ref<Platform> platform,
			uint8_t baseConfidence = BN_FULL_CONFIDENCE,
			Ref<Type> parentType = nullptr,
			BNTokenEscapingType escaping = NoTokenEscapingType
		) = 0;

		/*!
		    Generate a single-line text representation of a type
		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param name Name of the type
		    \param escaping Style of escaping literals which may not be parsable
		    \return String representing the type
		 */
		virtual std::string GetTypeString(
			Ref<Type> type,
			Ref<Platform> platform,
			const QualifiedName& name,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);
		/*!
		    In a single-line text representation of a type, generate the string that should
		    be printed before the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param escaping Style of escaping literals which may not be parsable
		    \return String representing the type
		 */
		virtual std::string GetTypeStringBeforeName(
			Ref<Type> type,
			Ref<Platform> platform,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);
		/*!
		    In a single-line text representation of a type, generate the string that should
		    be printed after the type's name.

		    \param type Type to print
		    \param platform Platform responsible for this type
		    \param escaping Style of escaping literals which may not be parsable
		    \return String representing the type
		 */
		virtual std::string GetTypeStringAfterName(
			Ref<Type> type,
			Ref<Platform> platform,
			BNTokenEscapingType escaping = NoTokenEscapingType
		);

		/*!
		    Generate a multi-line representation of a type
		    \param type Type to print
		    \param data Binary View in which the type is defined
		    \param name Name of the type
		    \param lineWidth Maximum width of lines, in characters
		    \param collapsed Whether to collapse structure/enum blocks
		    \param escaping Style of escaping literals which may not be parsable
		    \return List of type definition lines
		 */
		virtual std::vector<TypeDefinitionLine> GetTypeLines(
			Ref<Type> type,
			Ref<BinaryView> data,
			const QualifiedName& name,
			int lineWidth = 80,
			bool collapsed = false,
			BNTokenEscapingType escaping = NoTokenEscapingType
		) = 0;
	};

	class CoreTypePrinter: public TypePrinter
	{
	  public:
		CoreTypePrinter(BNTypePrinter* printer);
		virtual ~CoreTypePrinter() {}

		virtual std::vector<InstructionTextToken> GetTypeTokens(Ref<Type> type,
			Ref<Platform> platform, const QualifiedName& name,
			uint8_t baseConfidence, BNTokenEscapingType escaping) override;
		virtual std::vector<InstructionTextToken> GetTypeTokensBeforeName(Ref<Type> type,
			Ref<Platform> platform, uint8_t baseConfidence,
			Ref<Type> parentType, BNTokenEscapingType escaping) override;
		virtual std::vector<InstructionTextToken> GetTypeTokensAfterName(Ref<Type> type,
			Ref<Platform> platform, uint8_t baseConfidence,
			Ref<Type> parentType, BNTokenEscapingType escaping) override;
		virtual std::string GetTypeString(Ref<Type> type, Ref<Platform> platform,
			const QualifiedName& name, BNTokenEscapingType escaping) override;
		virtual std::string GetTypeStringBeforeName(Ref<Type> type, Ref<Platform> platform,
			BNTokenEscapingType escaping) override;
		virtual std::string GetTypeStringAfterName(Ref<Type> type, Ref<Platform> platform,
			BNTokenEscapingType escaping) override;
		virtual std::vector<TypeDefinitionLine> GetTypeLines(Ref<Type> type,
			Ref<BinaryView> data, const QualifiedName& name, int lineWidth,
			bool collapsed, BNTokenEscapingType escaping) override;
	};

}