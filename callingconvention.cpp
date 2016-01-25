#include "binaryninjaapi.h"

using namespace std;
using namespace BinaryNinja;


CallingConvention::CallingConvention(BNCallingConvention* cc): m_callingConvention(cc)
{
}


CallingConvention::CallingConvention(Architecture* arch, const string& name)
{
	BNCustomCallingConvention cc;
	cc.context = this;
	cc.getCallerSavedRegisters = GetCallerSavedRegistersCallback;
	cc.getIntegerArgumentRegisters = GetIntegerArgumentRegistersCallback;
	cc.getFloatArgumentRegisters = GetFloatArgumentRegistersCallback;
	cc.freeRegisterList = FreeRegisterListCallback;
	cc.areArgumentRegistersSharedIndex = AreArgumentRegistersSharedIndexCallback;
	cc.isStackReservedForArgumentRegisters = IsStackReservedForArgumentRegistersCallback;
	cc.getIntegerReturnValueRegister = GetIntegerReturnValueRegisterCallback;
	cc.getHighIntegerReturnValueRegister = GetHighIntegerReturnValueRegisterCallback;
	cc.getFloatReturnValueRegister = GetFloatReturnValueRegisterCallback;

	m_callingConvention = BNCreateCallingConvention(arch->GetArchitectureObject(), name.c_str(), &cc);
}


CallingConvention::~CallingConvention()
{
	BNFreeCallingConvention(m_callingConvention);
}


uint32_t* CallingConvention::GetCallerSavedRegistersCallback(void* ctxt, size_t* count)
{
	CallingConvention* cc = (CallingConvention*)ctxt;
	vector<uint32_t> regs = cc->GetCallerSavedRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* CallingConvention::GetIntegerArgumentRegistersCallback(void* ctxt, size_t* count)
{
	CallingConvention* cc = (CallingConvention*)ctxt;
	vector<uint32_t> regs = cc->GetIntegerArgumentRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* CallingConvention::GetFloatArgumentRegistersCallback(void* ctxt, size_t* count)
{
	CallingConvention* cc = (CallingConvention*)ctxt;
	vector<uint32_t> regs = cc->GetFloatArgumentRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


void CallingConvention::FreeRegisterListCallback(void*, uint32_t* regs)
{
	delete[] regs;
}


bool CallingConvention::AreArgumentRegistersSharedIndexCallback(void* ctxt)
{
	CallingConvention* cc = (CallingConvention*)ctxt;
	return cc->AreArgumentRegistersSharedIndex();
}


bool CallingConvention::IsStackReservedForArgumentRegistersCallback(void* ctxt)
{
	CallingConvention* cc = (CallingConvention*)ctxt;
	return cc->IsStackReservedForArgumentRegisters();
}


uint32_t CallingConvention::GetIntegerReturnValueRegisterCallback(void* ctxt)
{
	CallingConvention* cc = (CallingConvention*)ctxt;
	return cc->GetIntegerReturnValueRegister();
}


uint32_t CallingConvention::GetHighIntegerReturnValueRegisterCallback(void* ctxt)
{
	CallingConvention* cc = (CallingConvention*)ctxt;
	return cc->GetHighIntegerReturnValueRegister();
}


uint32_t CallingConvention::GetFloatReturnValueRegisterCallback(void* ctxt)
{
	CallingConvention* cc = (CallingConvention*)ctxt;
	return cc->GetFloatReturnValueRegister();
}


Ref<Architecture> CallingConvention::GetArchitecture() const
{
	return new CoreArchitecture(BNGetCallingConventionArchitecture(m_callingConvention));
}


string CallingConvention::GetName() const
{
	char* str = BNGetCallingConventionName(m_callingConvention);
	string result = str;
	BNFreeString(str);
	return result;
}


vector<uint32_t> CallingConvention::GetCallerSavedRegisters()
{
	return vector<uint32_t>();
}


vector<uint32_t> CallingConvention::GetIntegerArgumentRegisters()
{
	return vector<uint32_t>();
}


vector<uint32_t> CallingConvention::GetFloatArgumentRegisters()
{
	return vector<uint32_t>();
}


bool CallingConvention::AreArgumentRegistersSharedIndex()
{
	return false;
}


bool CallingConvention::IsStackReservedForArgumentRegisters()
{
	return false;
}


uint32_t CallingConvention::GetHighIntegerReturnValueRegister()
{
	return BN_INVALID_REGISTER;
}


uint32_t CallingConvention::GetFloatReturnValueRegister()
{
	return BN_INVALID_REGISTER;
}


CoreCallingConvention::CoreCallingConvention(BNCallingConvention* cc): CallingConvention(cc)
{
}


vector<uint32_t> CoreCallingConvention::GetCallerSavedRegisters()
{
	size_t count;
	uint32_t* regs = BNGetCallerSavedRegisters(m_callingConvention, &count);
	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);
	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreCallingConvention::GetIntegerArgumentRegisters()
{
	size_t count;
	uint32_t* regs = BNGetIntegerArgumentRegisters(m_callingConvention, &count);
	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);
	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreCallingConvention::GetFloatArgumentRegisters()
{
	size_t count;
	uint32_t* regs = BNGetFloatArgumentRegisters(m_callingConvention, &count);
	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);
	BNFreeRegisterList(regs);
	return result;
}


bool CoreCallingConvention::AreArgumentRegistersSharedIndex()
{
	return BNAreArgumentRegistersSharedIndex(m_callingConvention);
}


bool CoreCallingConvention::IsStackReservedForArgumentRegisters()
{
	return BNIsStackReservedForArgumentRegisters(m_callingConvention);
}


uint32_t CoreCallingConvention::GetIntegerReturnValueRegister()
{
	return BNGetIntegerReturnValueRegister(m_callingConvention);
}


uint32_t CoreCallingConvention::GetHighIntegerReturnValueRegister()
{
	return BNGetHighIntegerReturnValueRegister(m_callingConvention);
}


uint32_t CoreCallingConvention::GetFloatReturnValueRegister()
{
	return BNGetFloatReturnValueRegister(m_callingConvention);
}
