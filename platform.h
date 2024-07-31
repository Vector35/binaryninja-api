#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <map>
#include <string>
#include <vector>

namespace BinaryNinja
{
	class Architecture;
	class BinaryView;
	class CallingConvention;
	class NamedTypeReference;
	class QualifiedName;
	struct QualifiedNameAndType;
	class Type;
	class TypeContainer;
	class TypeLibrary;

	/*!
	    Platform base class. This should be subclassed when creating a new platform

	 	\ingroup Platform
	*/
	class Platform : public CoreRefCountObject<BNPlatform, BNNewPlatformReference, BNFreePlatform>
	{
	  protected:
		Platform(Architecture* arch, const std::string& name);
		Platform(Architecture* arch, const std::string& name, const std::string& typeFile,
		    const std::vector<std::string>& includeDirs = std::vector<std::string>());

		static void InitCallback(void *ctxt, BNPlatform*);
		static void InitViewCallback(void* ctxt, BNBinaryView* view);
		static uint32_t* GetGlobalRegistersCallback(void* ctxt, size_t* count);
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs, size_t count);
		static BNType* GetGlobalRegisterTypeCallback(void* ctxt, uint32_t reg);
		static void AdjustTypeParserInputCallback(
			void* ctxt,
			BNTypeParser* parser,
			const char* const* argumentsIn,
			size_t argumentsLenIn,
			const char* const* sourceFileNamesIn,
			const char* const* sourceFileValuesIn,
			size_t sourceFilesLenIn,
			char*** argumentsOut,
			size_t* argumentsLenOut,
			char*** sourceFileNamesOut,
			char*** sourceFileValuesOut,
			size_t* sourceFilesLenOut
		);
		static void FreeTypeParserInputCallback(
			void* ctxt,
			char** arguments,
			size_t argumentsLen,
			char** sourceFileNames,
			char** sourceFileValues,
			size_t sourceFilesLen
		);
		static bool GetFallbackEnabledCallback(void* ctxt);

	  public:
		Platform(BNPlatform* platform);

		/*! Get the Architecture for this platform

			\return The platform architecture
		*/
		Ref<Architecture> GetArchitecture() const;

		/*! Get the name of this platform

			\return The platform namee
		*/
		std::string GetName() const;

		/*! Register a Platform

			\param os OS for the platform to register
			\param platform Platform to register
		*/
		static void Register(const std::string& os, Platform* platform);

		/*! Get a platform by name

			\param name Name of the platform to retrieve
			\return The Platform, if it exists
		*/
		static Ref<Platform> GetByName(const std::string& name);

		/*! Get the list of registered platforms

			\return The list of registered platforms
		*/
		static std::vector<Ref<Platform>> GetList();

		/*! Get the list of registered platforms by Architecture

			\param arch Architecture to get the registered platforms for
			\return The list of registered platforms by Architecture
		*/
		static std::vector<Ref<Platform>> GetList(Architecture* arch);

		/*! Get the list of registered platforms by os

			\param os OS to get the registered platforms for
			\return The list of registered platforms by Architecture
		*/
		static std::vector<Ref<Platform>> GetList(const std::string& os);

		/*! Get the list of registered platforms by OS and Architecture

			\param os OS to get the registered platforms for
			\param arch Architecture to get the registered platforms for
			\return The list of registered platforms
		*/
		static std::vector<Ref<Platform>> GetList(const std::string& os, Architecture* arch);

		/*! Get the list of operating systems

			\return The list of operating systems
		*/
		static std::vector<std::string> GetOSList();

		/*! Get the default calling convention for this platform

			\return The default calling convention
		*/
		Ref<CallingConvention> GetDefaultCallingConvention() const;

		/*! Get the cdecl CallingConvention

			\return The cdecl CallingConvention
		*/
		Ref<CallingConvention> GetCdeclCallingConvention() const;

		/*! Get the stdcall CallingConvention

			\return The stdcall CallingConvention
		*/
		Ref<CallingConvention> GetStdcallCallingConvention() const;

		/*! Get the fastcall CallingConvention

			\return The fastcall Calling Convention
		*/
		Ref<CallingConvention> GetFastcallCallingConvention() const;

		/*! Get the list of registered calling conventions

			\return The list of registered calling conventions
		*/
		std::vector<Ref<CallingConvention>> GetCallingConventions() const;

		/*! Get the syscall calling convention

			\return The syscall CallingConvention
		*/
		Ref<CallingConvention> GetSystemCallConvention() const;

		/*! Register a Calling Convention

			\param cc Calling Convention to register
		*/
		void RegisterCallingConvention(CallingConvention* cc);

		/*! Set the default calling convention

			\param cc The new default CallingConvention
		*/
		void RegisterDefaultCallingConvention(CallingConvention* cc);

		/*! Set the cdecl calling convention

			\param cc The new cdecl CallingConvention
		*/
		void RegisterCdeclCallingConvention(CallingConvention* cc);

		/*! Set the stdcall calling convention

			\param cc The new stdcall CallingConvention
		*/
		void RegisterStdcallCallingConvention(CallingConvention* cc);

		/*! Set the fastcall calling convention

			\param cc The new fastcall calling convention
		*/
		void RegisterFastcallCallingConvention(CallingConvention* cc);

		/*! Set the syscall calling convention

			\param cc The new syscall calling convention
		*/
		void SetSystemCallConvention(CallingConvention* cc);

		/*! Callback that will be called when the platform of a binaryview
		 * is set. Allows for the Platform to to do platform-specific
		 * processing of views just after finalization.
		 *
		 * \param view BinaryView that was just set to this Platform
		 */
		virtual void BinaryViewInit(BinaryView* view);

		/*! Get the global register list for this Platform
		 *
		 * Allows the Platform to override the global register list
		 * used by analysis.
		 */
		virtual std::vector<uint32_t> GetGlobalRegisters();

		/*! Get the type of a global register
		 *
		 * Called by analysis when the incoming register value of a
		 * global register is observed.
		 *
		 * \param reg The register being queried for type information.
		 */
		virtual Ref<Type> GetGlobalRegisterType(uint32_t reg);

		/*! Modify the input passed to the Type Parser with Platform-specific features.

			\param[in] parser Type Parser instance
			\param[in,out] arguments Arguments to the type parser
			\param[in,out] sourceFiles Source file names and contents
		 */
		virtual void AdjustTypeParserInput(
			Ref<class TypeParser> parser,
			std::vector<std::string>& arguments,
			std::vector<std::pair<std::string, std::string>>& sourceFiles
		);

		/*! Provide an option for platforms to decide whether to use
		 * the fallback type library.
		 *
		 * Allows the Platform to override it to false.
		 */
		virtual bool GetFallbackEnabled();

		Ref<Platform> GetRelatedPlatform(Architecture* arch);
		void AddRelatedPlatform(Architecture* arch, Platform* platform);
		/*! Get the list of related platforms for this platform

		 	\return A vector of Ref<Platform>s
		 */
		std::vector<Ref<Platform>> GetRelatedPlatforms();
		Ref<Platform> GetAssociatedPlatformByAddress(uint64_t& addr);

		/*! Get the list of platform-specific types

			\return A map of Platform Type QualifiedNames and Ref<Type>s
		*/
		std::map<QualifiedName, Ref<Type>> GetTypes();

		/*! Get the list of platform-specific variable definitions

			\return A map of Platform Variable QualifiedNames and Ref<Type>s
		*/
		std::map<QualifiedName, Ref<Type>> GetVariables();

		/*! Get the list of platform-specific function definitions

			\return A map of Platform Function QualifiedNames and Ref<Type>s
		*/
		std::map<QualifiedName, Ref<Type>> GetFunctions();

		/*! System calls for this platform

			\return A list of system calls for this platform
		*/
		std::map<uint32_t, QualifiedNameAndType> GetSystemCalls();

		std::vector<Ref<TypeLibrary>> GetTypeLibraries();

		std::vector<Ref<TypeLibrary>> GetTypeLibrariesByName(const std::string& name);

		/*! Type Container for all registered types in the Platform.
			\return Platform types Type Container
		 */
		TypeContainer GetTypeContainer();

		Ref<Type> GetTypeByName(const QualifiedName& name);
		Ref<Type> GetVariableByName(const QualifiedName& name);
		Ref<Type> GetFunctionByName(const QualifiedName& name, bool exactMatch = false);
		std::string GetSystemCallName(uint32_t n);
		Ref<Type> GetSystemCallType(uint32_t n);

		std::string GenerateAutoPlatformTypeId(const QualifiedName& name);
		Ref<NamedTypeReference> GenerateAutoPlatformTypeReference(
		    BNNamedTypeReferenceClass cls, const QualifiedName& name);
		std::string GetAutoPlatformTypeIdSource();

		/*! Parses the source string and any needed headers searching for them in
			the optional list of directories provided in ``includeDirs``.

		 	\note This API does not allow the source to rely on existing types that only exist in a specific view. Use BinaryView->ParseTypeString instead.

			\param source Source string to be parsed
			\param fileName Source Filename
			\param types map reference that Types will be copied into
			\param variables map reference that variables will be copied into
			\param functions map reference that functions will be copied into
			\param errors string reference that any errors will be copied into
			\param includeDirs optional list of directories to include for header searches
			\param autoTypeSource optional source of types if used for automatically generated types
			\return true on success, false otherwise
		*/
		bool ParseTypesFromSource(const std::string& source, const std::string& fileName,
		    std::map<QualifiedName, Ref<Type>>& types, std::map<QualifiedName, Ref<Type>>& variables,
		    std::map<QualifiedName, Ref<Type>>& functions, std::string& errors,
		    const std::vector<std::string>& includeDirs = std::vector<std::string>(),
		    const std::string& autoTypeSource = "");

		/*! Parses the source string and any needed headers searching for them in
			the optional list of directories provided in ``includeDirs``.

			\note This API does not allow the source to rely on existing types that only exist in a specific view. Use BinaryView->ParseTypeString instead.

			\param fileName Source Filename
			\param types map reference that Types will be copied into
			\param variables map reference that variables will be copied into
			\param functions map reference that functions will be copied into
			\param errors string reference that any errors will be copied into
			\param includeDirs optional list of directories to include for header searches
			\param autoTypeSource optional source of types if used for automatically generated types
			\return true on success, false otherwise
			\return
		*/
		bool ParseTypesFromSourceFile(const std::string& fileName, std::map<QualifiedName, Ref<Type>>& types,
		    std::map<QualifiedName, Ref<Type>>& variables, std::map<QualifiedName, Ref<Type>>& functions,
		    std::string& errors, const std::vector<std::string>& includeDirs = std::vector<std::string>(),
		    const std::string& autoTypeSource = "");
	};


	class CorePlatform : public Platform
	{
	public:
		CorePlatform(BNPlatform* plat);

		virtual std::vector<uint32_t> GetGlobalRegisters() override;
		virtual Ref<Type> GetGlobalRegisterType(uint32_t reg) override;
		virtual void AdjustTypeParserInput(
			Ref<class TypeParser> parser,
			std::vector<std::string>& arguments,
			std::vector<std::pair<std::string, std::string>>& sourceFiles
		) override;
	};

}
