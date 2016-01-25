#include "binaryninjaapi.h"

using namespace std;
using namespace BinaryNinja;


Platform::Platform(BNPlatform* platform): m_platform(platform)
{
}


Platform::Platform(Architecture* arch, const string& name)
{
	m_platform = BNCreatePlatform(arch->GetArchitectureObject(), name.c_str());
}


Platform::~Platform()
{
	BNFreePlatform(m_platform);
}


Ref<Architecture> Platform::GetArchitecture() const
{
	return new CoreArchitecture(BNGetPlatformArchitecture(m_platform));
}


string Platform::GetName() const
{
	char* str = BNGetPlatformName(m_platform);
	string result = str;
	BNFreeString(str);
	return result;
}


void Platform::Register(const string& os, Platform* platform)
{
	BNRegisterPlatform(os.c_str(), platform->GetPlatformObject());
}


Ref<Platform> Platform::GetByName(const string& name)
{
	BNPlatform* platform = BNGetPlatformByName(name.c_str());
	if (!platform)
		return nullptr;
	return new Platform(platform);
}


vector<Ref<Platform>> Platform::GetList()
{
	size_t count;
	BNPlatform** list = BNGetPlatformList(&count);

	vector<Ref<Platform>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Platform(BNNewPlatformReference(list[i])));

	BNFreePlatformList(list, count);
	return result;
}


vector<Ref<Platform>> Platform::GetList(Architecture* arch)
{
	size_t count;
	BNPlatform** list = BNGetPlatformListByArchitecture(arch->GetArchitectureObject(), &count);

	vector<Ref<Platform>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Platform(BNNewPlatformReference(list[i])));

	BNFreePlatformList(list, count);
	return result;
}


vector<Ref<Platform>> Platform::GetList(const string& os)
{
	size_t count;
	BNPlatform** list = BNGetPlatformListByOS(os.c_str(), &count);

	vector<Ref<Platform>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Platform(BNNewPlatformReference(list[i])));

	BNFreePlatformList(list, count);
	return result;
}


vector<Ref<Platform>> Platform::GetList(const string& os, Architecture* arch)
{
	size_t count;
	BNPlatform** list = BNGetPlatformListByOSAndArchitecture(os.c_str(), arch->GetArchitectureObject(), &count);

	vector<Ref<Platform>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new Platform(BNNewPlatformReference(list[i])));

	BNFreePlatformList(list, count);
	return result;
}


vector<std::string> Platform::GetOSList()
{
	size_t count;
	char** list = BNGetPlatformOSList(&count);

	vector<string> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(list[i]);

	BNFreePlatformOSList(list, count);
	return result;
}


Ref<CallingConvention> Platform::GetDefaultCallingConvention() const
{
	BNCallingConvention* cc = BNGetPlatformDefaultCallingConvention(m_platform);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


Ref<CallingConvention> Platform::GetCdeclCallingConvention() const
{
	BNCallingConvention* cc = BNGetPlatformCdeclCallingConvention(m_platform);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


Ref<CallingConvention> Platform::GetStdcallCallingConvention() const
{
	BNCallingConvention* cc = BNGetPlatformStdcallCallingConvention(m_platform);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


Ref<CallingConvention> Platform::GetFastcallCallingConvention() const
{
	BNCallingConvention* cc = BNGetPlatformFastcallCallingConvention(m_platform);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


vector<Ref<CallingConvention>> Platform::GetCallingConventions() const
{
	size_t count;
	BNCallingConvention** list = BNGetPlatformCallingConventions(m_platform, &count);

	vector<Ref<CallingConvention>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreCallingConvention(BNNewCallingConventionReference(list[i])));

	BNFreeCallingConventionList(list, count);
	return result;
}


void Platform::RegisterCallingConvention(CallingConvention* cc)
{
	BNRegisterPlatformCallingConvention(m_platform, cc->GetCallingConventionObject());
}


void Platform::RegisterDefaultCallingConvention(CallingConvention* cc)
{
	BNRegisterPlatformDefaultCallingConvention(m_platform, cc->GetCallingConventionObject());
}


void Platform::RegisterCdeclCallingConvention(CallingConvention* cc)
{
	BNRegisterPlatformCdeclCallingConvention(m_platform, cc->GetCallingConventionObject());
}


void Platform::RegisterStdcallCallingConvention(CallingConvention* cc)
{
	BNRegisterPlatformStdcallCallingConvention(m_platform, cc->GetCallingConventionObject());
}


void Platform::RegisterFastcallCallingConvention(CallingConvention* cc)
{
	BNRegisterPlatformFastcallCallingConvention(m_platform, cc->GetCallingConventionObject());
}


Ref<Platform> Platform::GetRelatedPlatform(Architecture* arch)
{
	BNPlatform* platform = BNGetRelatedPlatform(m_platform, arch->GetArchitectureObject());
	if (!platform)
		return nullptr;
	return new Platform(platform);
}


void Platform::AddRelatedPlatform(Architecture* arch, Platform* platform)
{
	BNAddRelatedPlatform(m_platform, arch->GetArchitectureObject(), platform->GetPlatformObject());
}
