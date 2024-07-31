#pragma once

#include "binaryninjacore.h"
#include "namelist.h"
#include "refcount.h"
#include <optional>
#include <string>
#include <vector>

namespace BinaryNinja
{
	class Platform;
	struct QualifiedNameAndType;
	class Type;
	class TypeContainer;

	/*!
		\ingroup typeparser
	*/
	struct ParsedType
	{
		QualifiedName name;
		Ref<Type> type;
		bool isUser;

		ParsedType() = default;
		ParsedType(const std::string& name, const Ref<Type>& type, bool isUser): name(name), type(type), isUser(isUser)
		{}
		ParsedType(const QualifiedName& name, const Ref<Type>& type, bool isUser): name(name), type(type), isUser(isUser)
		{}

		bool operator<(const ParsedType& other) const
		{
			if (isUser != other.isUser)
				return isUser;
			return name < other.name;
		}
	};

	/*!
		\ingroup typeparser
	*/
	struct TypeParserResult
	{
		std::vector<ParsedType> types;
		std::vector<ParsedType> variables;
		std::vector<ParsedType> functions;
	};

	/*!
		\ingroup typeparser
	*/
	struct TypeParserError
	{
		BNTypeParserErrorSeverity severity;
		std::string message;
		std::string fileName;
		uint64_t line;
		uint64_t column;

		TypeParserError() = default;
		TypeParserError(BNTypeParserErrorSeverity severity, const std::string& message):
			severity(severity), message(message), fileName(""), line(0), column(0)
		{

		}
	};


	/*!
		\ingroup typeparser
	*/
	class TypeParser: public StaticCoreRefCountObject<BNTypeParser>
	{
		std::string m_nameForRegister;
	  protected:
		explicit TypeParser(const std::string& name);
		TypeParser(BNTypeParser* parser);

		static bool GetOptionTextCallback(void* ctxt, BNTypeParserOption option, const char* value, char** result);
		static bool PreprocessSourceCallback(void* ctxt,
			const char* source, const char* fileName, BNPlatform* platform,
			BNTypeContainer* existingTypes,
			const char* const* options, size_t optionCount,
			const char* const* includeDirs, size_t includeDirCount,
			char** output, BNTypeParserError** errors, size_t* errorCount
		);
		static bool ParseTypesFromSourceCallback(void* ctxt,
			const char* source, const char* fileName, BNPlatform* platform,
			BNTypeContainer* existingTypes,
			const char* const* options, size_t optionCount,
			const char* const* includeDirs, size_t includeDirCount,
			const char* autoTypeSource, BNTypeParserResult* result,
			BNTypeParserError** errors, size_t* errorCount
		);
		static bool ParseTypeStringCallback(void* ctxt,
			const char* source, BNPlatform* platform,
			BNTypeContainer* existingTypes,
			BNQualifiedNameAndType* result,
			BNTypeParserError** errors, size_t* errorCount
		);
		static void FreeStringCallback(void* ctxt, char* result);
		static void FreeResultCallback(void* ctxt, BNTypeParserResult* result);
		static void FreeErrorListCallback(void* ctxt, BNTypeParserError* errors, size_t errorCount);

	  public:
		static void Register(TypeParser* parser);
		static std::vector<Ref<TypeParser>> GetList();
		static Ref<TypeParser> GetByName(const std::string& name);
		static Ref<TypeParser> GetDefault();

		/*!
		    Parse a space-separated string of options into a list
		    \param optionsText Space-separated options text
		    \return List of options
		*/
		static std::vector<std::string> ParseOptionsText(const std::string& optionsText);

		/*!
		    Format a list of parser errors into a big string
		    \param errors List of errors
		    \return String of formatted errors
		*/
		static std::string FormatParseErrors(const std::vector<TypeParserError>& errors);

		/*!
		    Get the Type Parser's registered name
		    \return Parser name
		 */
		std::string GetName() const;

		/**
		    Get the string representation of an option for passing to ParseTypes*
		    \param option Option type
		    \param value Option value
		    \param result String representing the option
		    \return True if the parser supports the option
		*/
		virtual bool GetOptionText(BNTypeParserOption option, std::string value, std::string& result) const;

		/*!
		    Preprocess a block of source, returning the source that would be parsed
		    \param source Source code to process
		    \param fileName Name of the file containing the source (does not need to exist on disk)
		    \param platform Platform to assume the source is relevant to
		    \param existingTypes Container of all existing types to use for parsing context
		    \param options String arguments to pass as options, e.g. command line arguments
		    \param includeDirs List of directories to include in the header search path
		    \param output Reference to a string into which the preprocessed source will be written
		    \param errors Reference to a list into which any parse errors will be written
		    \return True if preprocessing was successful
		*/
		virtual bool PreprocessSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			std::string& output,
			std::vector<TypeParserError>& errors
		) = 0;

		/*!
		    Parse an entire block of source into types, variables, and functions
		    \param source Source code to parse
		    \param fileName Name of the file containing the source (optional: exists on disk)
		    \param platform Platform to assume the types are relevant to
		    \param existingTypes Container of all existing types to use for parsing context
		    \param options String arguments to pass as options, e.g. command line arguments
		    \param includeDirs List of directories to include in the header search path
		    \param autoTypeSource Optional source of types if used for automatically generated types
		    \param result Reference to structure into which the results will be written
		    \param errors Reference to a list into which any parse errors will be written
		    \return True if parsing was successful
		*/
		virtual bool ParseTypesFromSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		) = 0;

		/*!
		    Parse an entire source file into types, variables, and functions
		    \param fileName Name of the file on disk containing the source
		    \param platform Platform to assume the types are relevant to
		    \param existingTypes Container of all existing types to use for parsing context
		    \param options String arguments to pass as options, e.g. command line arguments
		    \param includeDirs List of directories to include in the header search path
		    \param autoTypeSource Optional source of types if used for automatically generated types
		    \param result Reference to structure into which the results will be written
		    \param errors Reference to a list into which any parse errors will be written
		    \return True if parsing was successful
		*/
		bool ParseTypesFromSourceFile(
			const std::string& fileName,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		);

		/*!
		    Parse a single type and name from a string containing their definition.
		    \param source Source code to parse
		    \param platform Platform to assume the types are relevant to
		    \param existingTypes Container of all existing types to use for parsing context
		    \param result Reference into which the resulting type and name will be written
		    \param errors Reference to a list into which any parse errors will be written
		    \return True if parsing was successful
		*/
		virtual bool ParseTypeString(
			const std::string& source,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			QualifiedNameAndType& result,
			std::vector<TypeParserError>& errors
		) = 0;
	};

	/*!
		\ingroup typeparser
	*/
	class CoreTypeParser: public TypeParser
	{
	  public:
		CoreTypeParser(BNTypeParser* parser);
		virtual ~CoreTypeParser() {}

		virtual bool GetOptionText(BNTypeParserOption option, std::string value, std::string& result) const override;

		virtual bool PreprocessSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			std::string& output,
			std::vector<TypeParserError>& errors
		) override;

		virtual bool ParseTypesFromSource(
			const std::string& source,
			const std::string& fileName,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			const std::vector<std::string>& options,
			const std::vector<std::string>& includeDirs,
			const std::string& autoTypeSource,
			TypeParserResult& result,
			std::vector<TypeParserError>& errors
		) override;

		virtual bool ParseTypeString(
			const std::string& source,
			Ref<Platform> platform,
			std::optional<TypeContainer> existingTypes,
			QualifiedNameAndType& result,
			std::vector<TypeParserError>& errors
		) override;
	};
}
