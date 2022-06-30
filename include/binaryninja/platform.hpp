#pragma once
#include <string>
#include <vector>
#include <map>

#include "binaryninjacore/platform.h"
#include "binaryninjacore/binaryninja_defs.h"
#include "refcount.hpp"

namespace BinaryNinja {
	/*!
		Platform base class. This should be subclassed when creating a new platform
	 */
	class Architecture;
	class CallingConvention;
	class NamedTypeReference;
	class QualifiedName;
	class QualifiedNameAndType;
	class Type;

	class Platform : public CoreRefCountObject<BNPlatform, BNNewPlatformReference, BNFreePlatform>
	{
	  protected:
		Platform(Architecture* arch, const std::string& name);
		Platform(Architecture* arch, const std::string& name, const std::string& typeFile,
			const std::vector<std::string>& includeDirs = std::vector<std::string>());

	  public:
		Platform(BNPlatform* platform);

		Ref<Architecture> GetArchitecture() const;
		std::string GetName() const;

		static void Register(const std::string& os, Platform* platform);
		static Ref<Platform> GetByName(const std::string& name);
		static std::vector<Ref<Platform>> GetList();
		static std::vector<Ref<Platform>> GetList(Architecture* arch);
		static std::vector<Ref<Platform>> GetList(const std::string& os);
		static std::vector<Ref<Platform>> GetList(const std::string& os, Architecture* arch);
		static std::vector<std::string> GetOSList();

		Ref<CallingConvention> GetDefaultCallingConvention() const;
		Ref<CallingConvention> GetCdeclCallingConvention() const;
		Ref<CallingConvention> GetStdcallCallingConvention() const;
		Ref<CallingConvention> GetFastcallCallingConvention() const;
		std::vector<Ref<CallingConvention>> GetCallingConventions() const;
		Ref<CallingConvention> GetSystemCallConvention() const;

		void RegisterCallingConvention(CallingConvention* cc);
		void RegisterDefaultCallingConvention(CallingConvention* cc);
		void RegisterCdeclCallingConvention(CallingConvention* cc);
		void RegisterStdcallCallingConvention(CallingConvention* cc);
		void RegisterFastcallCallingConvention(CallingConvention* cc);
		void SetSystemCallConvention(CallingConvention* cc);

		Ref<Platform> GetRelatedPlatform(Architecture* arch);
		void AddRelatedPlatform(Architecture* arch, Platform* platform);
		Ref<Platform> GetAssociatedPlatformByAddress(uint64_t& addr);

		std::map<QualifiedName, Ref<Type>> GetTypes();
		std::map<QualifiedName, Ref<Type>> GetVariables();
		std::map<QualifiedName, Ref<Type>> GetFunctions();
		std::map<uint32_t, QualifiedNameAndType> GetSystemCalls();
		Ref<Type> GetTypeByName(const QualifiedName& name);
		Ref<Type> GetVariableByName(const QualifiedName& name);
		Ref<Type> GetFunctionByName(const QualifiedName& name, bool exactMatch = false);
		std::string GetSystemCallName(uint32_t n);
		Ref<Type> GetSystemCallType(uint32_t n);

		std::string GenerateAutoPlatformTypeId(const QualifiedName& name);
		Ref<NamedTypeReference> GenerateAutoPlatformTypeReference(
			BNNamedTypeReferenceClass cls, const QualifiedName& name);
		std::string GetAutoPlatformTypeIdSource();

		bool ParseTypesFromSource(const std::string& source, const std::string& fileName,
			std::map<QualifiedName, Ref<Type>>& types, std::map<QualifiedName, Ref<Type>>& variables,
			std::map<QualifiedName, Ref<Type>>& functions, std::string& errors,
			const std::vector<std::string>& includeDirs = std::vector<std::string>(),
			const std::string& autoTypeSource = "");
		bool ParseTypesFromSourceFile(const std::string& fileName, std::map<QualifiedName, Ref<Type>>& types,
			std::map<QualifiedName, Ref<Type>>& variables, std::map<QualifiedName, Ref<Type>>& functions,
			std::string& errors, const std::vector<std::string>& includeDirs = std::vector<std::string>(),
			const std::string& autoTypeSource = "");
	};
}