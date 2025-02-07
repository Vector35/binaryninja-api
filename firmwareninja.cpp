// Copyright (c) 2015-2024 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "binaryninjaapi.h"
#include "binaryninjacore.h"

using namespace BinaryNinja;


static BNFirmwareNinjaFunctionMemoryAccesses** MemoryInfoVectorToArray(
	const std::vector<FirmwareNinjaFunctionMemoryAccesses>& fma)
{
	BNFirmwareNinjaFunctionMemoryAccesses** result = new BNFirmwareNinjaFunctionMemoryAccesses*[fma.size()];
	for (size_t i = 0; i < fma.size(); i++)
	{
		result[i] = new BNFirmwareNinjaFunctionMemoryAccesses;
		result[i]->start = fma[i].start;
		result[i]->count = fma[i].count;
		result[i]->accesses = new BNFirmwareNinjaMemoryAccess*[fma[i].count];
		for (size_t j = 0; j < fma[i].count; j++)
		{
			result[i]->accesses[j] = new BNFirmwareNinjaMemoryAccess;
			std::memcpy(result[i]->accesses[j], &fma[i].accesses[j], sizeof(BNFirmwareNinjaMemoryAccess));
		}
	}

	return result;
}


static void FreeMemoryInfoArray(BNFirmwareNinjaFunctionMemoryAccesses** fma, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		for (size_t j = 0; j < fma[i]->count; j++)
			delete fma[i]->accesses[j];

		delete[] fma[i]->accesses;
		delete fma[i];
	}
}


FirmwareNinjaRelationship::FirmwareNinjaRelationship(Ref<BinaryView> view, BNFirmwareNinjaRelationship* handle)
{
	if (handle)
		m_object = handle;
	else
		m_object = BNNewFirmwareNinjaRelationshipReference(BNCreateFirmwareNinjaRelationship(view->GetObject()));
}


FirmwareNinjaRelationship::~FirmwareNinjaRelationship()
{
	BNFreeFirmwareNinjaRelationship(m_object);
}


void FirmwareNinjaRelationship::SetPrimaryAddress(uint64_t address)
{
	BNFirmwareNinjaRelationshipSetPrimaryAddress(m_object, address);
}


void FirmwareNinjaRelationship::SetPrimaryDataVariable(DataVariable& variable)
{
	BNFirmwareNinjaRelationshipSetPrimaryDataVariable(m_object, variable.address);
}


void FirmwareNinjaRelationship::SetPrimaryFunction(Ref<Function> function)
{
	BNFirmwareNinjaRelationshipSetPrimaryFunction(m_object, function->GetObject());
}


bool FirmwareNinjaRelationship::PrimaryIsAddress() const
{
	return BNFirmwareNinjaRelationshipPrimaryIsAddress(m_object);
}


bool FirmwareNinjaRelationship::PrimaryIsDataVariable() const
{
	return BNFirmwareNinjaRelationshipPrimaryIsDataVariable(m_object);
}


bool FirmwareNinjaRelationship::PrimaryIsFunction() const
{
	return BNFirmwareNinjaRelationshipPrimaryIsFunction(m_object);
}


bool FirmwareNinjaRelationship::GetPrimaryDataVariable(DataVariable& variable)
{
	BNDataVariable bnVariable;
	if (!BNFirmwareNinjaRelationshipGetPrimaryDataVariable(m_object, &bnVariable))
		return false;

	variable.address = bnVariable.address;
	variable.type = Confidence(new Type(BNNewTypeReference(bnVariable.type)), bnVariable.typeConfidence);
	variable.autoDiscovered = bnVariable.autoDiscovered;
	BNFreeDataVariable(&bnVariable);
	return true;
}


std::optional<uint64_t> FirmwareNinjaRelationship::GetPrimaryAddress() const
{
	std::optional<uint64_t> result;
	uint64_t tmp;
	if (BNFirmwareNinjaRelationshipGetPrimaryAddress(m_object, &tmp))
		result = tmp;

	return result;
}


Ref<Function> FirmwareNinjaRelationship::GetPrimaryFunction() const
{
	auto bnFunction = BNFirmwareNinjaRelationshipGetPrimaryFunction(m_object);
	if (!bnFunction)
		return nullptr;

	return new Function(BNNewFunctionReference(bnFunction));
}


void FirmwareNinjaRelationship::SetSecondaryAddress(uint64_t address)
{
	BNFirmwareNinjaRelationshipSetSecondaryAddress(m_object, address);
}


void FirmwareNinjaRelationship::SetSecondaryDataVariable(DataVariable& variable)
{
	BNFirmwareNinjaRelationshipSetSecondaryDataVariable(m_object, variable.address);
}


void FirmwareNinjaRelationship::SetSecondaryFunction(Ref<Function> function)
{
	BNFirmwareNinjaRelationshipSetSecondaryFunction(m_object, function->GetObject());
}


void FirmwareNinjaRelationship::SetSecondaryExternalAddress(Ref<ProjectFile> projectFile, uint64_t address)
{
	BNFirmwareNinjaRelationshipSetSecondaryExternalAddress(m_object, projectFile->GetObject(), address);
}


void FirmwareNinjaRelationship::SetSecondaryExternalSymbol(Ref<ProjectFile> projectFile, const std::string& symbol)
{
	BNFirmwareNinjaRelationshipSetSecondaryExternalSymbol(m_object, projectFile->GetObject(), symbol.c_str());
}


bool FirmwareNinjaRelationship::SecondaryIsAddress() const
{
	return BNFirmwareNinjaRelationshipSecondaryIsAddress(m_object);
}


bool FirmwareNinjaRelationship::SecondaryIsDataVariable() const
{
	return BNFirmwareNinjaRelationshipSecondaryIsDataVariable(m_object);
}


bool FirmwareNinjaRelationship::SecondaryIsFunction() const
{
	return BNFirmwareNinjaRelationshipSecondaryIsFunction(m_object);
}


bool FirmwareNinjaRelationship::SecondaryIsExternalAddress() const
{
	return BNFirmwareNinjaRelationshipSecondaryIsExternalAddress(m_object);
}


bool FirmwareNinjaRelationship::SecondaryIsExternalSymbol() const
{
	return BNFirmwareNinjaRelationshipSecondaryIsExternalSymbol(m_object);
}


Ref<ProjectFile> FirmwareNinjaRelationship::GetSecondaryExternalProjectFile() const
{
	auto bnProjectFile = BNFirmwareNinjaRelationshipGetSecondaryExternalProjectFile(m_object);
	if (!bnProjectFile)
		return nullptr;

	return new ProjectFile(BNNewProjectFileReference(bnProjectFile));
}


std::optional<uint64_t> FirmwareNinjaRelationship::GetSecondaryAddress() const
{
	std::optional<uint64_t> result;
	uint64_t tmp;
	if (BNFirmwareNinjaRelationshipGetSecondaryAddress(m_object, &tmp))
		result = tmp;

	return result;
}


bool FirmwareNinjaRelationship::GetSecondaryDataVariable(DataVariable& variable)
{
	BNDataVariable bnVariable;
	if (!BNFirmwareNinjaRelationshipGetSecondaryDataVariable(m_object, &bnVariable))
		return false;

	variable.address = bnVariable.address;
	variable.type = Confidence(new Type(BNNewTypeReference(bnVariable.type)), bnVariable.typeConfidence);
	variable.autoDiscovered = bnVariable.autoDiscovered;
	BNFreeDataVariable(&bnVariable);
	return true;
}


Ref<Function> FirmwareNinjaRelationship::GetSecondaryFunction() const
{
	auto bnFunction = BNFirmwareNinjaRelationshipGetSecondaryFunction(m_object);
	if (!bnFunction)
		return nullptr;

	return new Function(BNNewFunctionReference(bnFunction));
}


std::string FirmwareNinjaRelationship::GetSecondaryExternalSymbol() const
{
	std::string result = "";
	auto bnSymbol = BNFirmwareNinjaRelationshipGetSecondaryExternalSymbol(m_object);
	if (bnSymbol)
		result = std::string(bnSymbol);

	return result;
}


void FirmwareNinjaRelationship::SetDescription(const std::string& description)
{
	BNFirmwareNinjaRelationshipSetDescription(m_object, description.c_str());
}


std::string FirmwareNinjaRelationship::GetDescription() const
{
	std::string result = "";
	auto bnDescription = BNFirmwareNinjaRelationshipGetDescription(m_object);
	if (bnDescription)
		result = std::string(bnDescription);

	return result;
}


void FirmwareNinjaRelationship::SetProvenance(const std::string& provenance)
{
	BNFirmwareNinjaRelationshipSetProvenance(m_object, provenance.c_str());
}


std::string FirmwareNinjaRelationship::GetProvenance() const
{
	std::string result = "";
	auto bnProvenance = BNFirmwareNinjaRelationshipGetProvenance(m_object);
	if (bnProvenance)
		result = std::string(bnProvenance);

	return result;
}


std::string FirmwareNinjaRelationship::GetGuid() const
{
	return BNFirmwareNinjaRelationshipGetGuid(m_object);
}


FirmwareNinjaReferenceNode::FirmwareNinjaReferenceNode(BNFirmwareNinjaReferenceNode* node)
{
	m_object = node;
}


FirmwareNinjaReferenceNode::~FirmwareNinjaReferenceNode()
{
	BNFreeFirmwareNinjaReferenceNode(m_object);
}


bool FirmwareNinjaReferenceNode::IsFunction()
{
	return BNFirmwareNinjaReferenceNodeIsFunction(m_object);
}


bool FirmwareNinjaReferenceNode::IsDataVariable()
{
	return BNFirmwareNinjaReferenceNodeIsDataVariable(m_object);
}


bool FirmwareNinjaReferenceNode::HasChildren()
{
	return BNFirmwareNinjaReferenceNodeHasChildren(m_object);
}


bool FirmwareNinjaReferenceNode::GetFunction(Ref<Function>& function)
{
	auto bnFunction = BNFirmwareNinjaReferenceNodeGetFunction(m_object);
	if (!bnFunction)
		return false;

	function = new Function(BNNewFunctionReference(bnFunction));
	return true;
}


bool FirmwareNinjaReferenceNode::GetDataVariable(DataVariable& variable)
{
	BNDataVariable bnVariable;
	if (!BNFirmwareNinjaReferenceNodeGetDataVariable(m_object, &bnVariable))
		return false;

	variable.address = bnVariable.address;
	variable.type = Confidence(new Type(BNNewTypeReference(bnVariable.type)), bnVariable.typeConfidence);
	variable.autoDiscovered = bnVariable.autoDiscovered;
	BNFreeDataVariable(&bnVariable);
	return true;
}


std::vector<Ref<FirmwareNinjaReferenceNode>> FirmwareNinjaReferenceNode::GetChildren()
{
	std::vector<Ref<FirmwareNinjaReferenceNode>> result;
	size_t count = 0;
	auto bnChildren = BNFirmwareNinjaReferenceNodeGetChildren(m_object, &count);
	result.reserve(count);
	for (size_t i = 0; i < count; ++i)
	{
		result.push_back(new FirmwareNinjaReferenceNode(
			BNNewFirmwareNinjaReferenceNodeReference(bnChildren[i])));
	}

	return result;
}


FirmwareNinja::FirmwareNinja(Ref<BinaryView> view)
{
	m_view = view;
	m_object = BNCreateFirmwareNinja(view->GetObject());
}


FirmwareNinja::~FirmwareNinja()
{
	BNFreeFirmwareNinja(m_object);
}


bool FirmwareNinja::StoreCustomDevice(FirmwareNinjaDevice& device)
{
	return BNFirmwareNinjaStoreCustomDevice(m_object, device.name.c_str(),
		device.start, device.end, device.info.c_str());
}


bool FirmwareNinja::RemoveCustomDevice(const std::string& name)
{
	return BNFirmwareNinjaRemoveCustomDevice(m_object, name.c_str());
}


std::vector<FirmwareNinjaDevice> FirmwareNinja::QueryCustomDevices()
{
	std::vector<FirmwareNinjaDevice> result;
	BNFirmwareNinjaDevice* devices;
	int count = BNFirmwareNinjaQueryCustomDevices(m_object, &devices);
	if (count <= 0)
		return result;

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back({
			devices[i].name,
			devices[i].start,
			devices[i].end,
			devices[i].info
		});

	BNFirmwareNinjaFreeDevices(devices, count);
	return result;
}


std::vector<std::string> FirmwareNinja::QueryBoardNames()
{
	std::vector<std::string> result;
	char** boards;
	auto platform = m_view->GetDefaultPlatform();
	if (!platform)
		return result;

	auto arch = platform->GetArchitecture();
	if (!arch)
		return result;

	int count = BNFirmwareNinjaQueryBoardNamesForArchitecture(m_object, arch->GetObject(), &boards);
	if (count <= 0)
		return result;

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(boards[i]);

	BNFirmwareNinjaFreeBoardNames(boards, count);
	sort(result.begin(), result.end());
	return result;
}


std::vector<FirmwareNinjaDevice> FirmwareNinja::QueryDevicesForBoard(const std::string& board)
{
	std::vector<FirmwareNinjaDevice> result;
	BNFirmwareNinjaDevice* devices;
	auto platform = m_view->GetDefaultPlatform();
	if (!platform)
		return result;

	auto arch = platform->GetArchitecture();
	if (!arch)
		return result;

	int count = BNFirmwareNinjaQueryBoardDevices(m_object, arch->GetObject(), board.c_str(), &devices);
	if (count <= 0)
		return result;

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back({
			devices[i].name,
			devices[i].start,
			devices[i].end,
			devices[i].info
		});

	BNFirmwareNinjaFreeDevices(devices, count);
	return result;
}


std::vector<BNFirmwareNinjaSection> FirmwareNinja::FindSections(float highCodeEntropyThreshold,
	float lowCodeEntropyThreshold, size_t blockSize, BNFirmwareNinjaSectionAnalysisMode mode)
{
	std::vector<BNFirmwareNinjaSection> result;
	BNFirmwareNinjaSection* sections;
	int count = BNFirmwareNinjaFindSectionsWithEntropy(m_object, &sections, highCodeEntropyThreshold,
		lowCodeEntropyThreshold, blockSize, mode);
	if (count <= 0)
		return result;

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(sections[i]);

	BNFirmwareNinjaFreeSections(sections, count);
	return result;
}


std::vector<FirmwareNinjaFunctionMemoryAccesses> FirmwareNinja::GetFunctionMemoryAccesses(BNProgressFunction progress,
	void* progressContext)
{
	std::vector<FirmwareNinjaFunctionMemoryAccesses> result;
	BNFirmwareNinjaFunctionMemoryAccesses** fma;
	int count = BNFirmwareNinjaGetFunctionMemoryAccesses(m_object, &fma, progress, progressContext);
	if (count <= 0)
		return result;

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		FirmwareNinjaFunctionMemoryAccesses info;
		info.start = fma[i]->start;
		info.count = fma[i]->count;
		for (size_t j = 0; j < info.count; j++)
		{
			BNFirmwareNinjaMemoryAccess access;
			std::memcpy(&access, fma[i]->accesses[j], sizeof(BNFirmwareNinjaMemoryAccess));
			info.accesses.push_back(access);
		}

		result.push_back(info);
	}

	BNFirmwareNinjaFreeFunctionMemoryAccesses(fma, count);
	std::sort(result.begin(), result.end(), [](const FirmwareNinjaFunctionMemoryAccesses& a,
		const FirmwareNinjaFunctionMemoryAccesses& b) {
		return a.count > b.count;
	});

	return result;
}


void FirmwareNinja::StoreFunctionMemoryAccesses(const std::vector<FirmwareNinjaFunctionMemoryAccesses>& fma)
{
	if (fma.empty())
		return;

	BNFirmwareNinjaFunctionMemoryAccesses** fmaArray = MemoryInfoVectorToArray(fma);
	BNFirmwareNinjaStoreFunctionMemoryAccessesToMetadata(m_object, fmaArray, fma.size());
	FreeMemoryInfoArray(fmaArray, fma.size());
}


std::vector<FirmwareNinjaFunctionMemoryAccesses> FirmwareNinja::QueryFunctionMemoryAccesses()
{
	std::vector<FirmwareNinjaFunctionMemoryAccesses> result;
	BNFirmwareNinjaFunctionMemoryAccesses** fma;
	int count = BNFirmwareNinjaQueryFunctionMemoryAccessesFromMetadata(m_object, &fma);
	if (count <= 0)
		return result;

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		FirmwareNinjaFunctionMemoryAccesses info;
		info.start = fma[i]->start;
		info.count = fma[i]->count;
		for (size_t j = 0; j < info.count; j++)
		{
			BNFirmwareNinjaMemoryAccess access;
			std::memcpy(&access, fma[i]->accesses[j], sizeof(BNFirmwareNinjaMemoryAccess));
			info.accesses.push_back(access);
		}

		result.push_back(info);
	}

	BNFirmwareNinjaFreeFunctionMemoryAccesses(fma, count);
	std::sort(result.begin(), result.end(), [](const FirmwareNinjaFunctionMemoryAccesses& a,
		const FirmwareNinjaFunctionMemoryAccesses& b) {
		return a.count > b.count;
	});

	return result;
}


std::vector<FirmwareNinjaDeviceAccesses> FirmwareNinja::GetBoardDeviceAccesses(
	const std::vector<FirmwareNinjaFunctionMemoryAccesses>& fma)
{
	std::vector<FirmwareNinjaDeviceAccesses> result;
	if (fma.empty())
		return result;

	auto platform = m_view->GetDefaultPlatform();
	if (!platform)
		return result;

	auto arch = platform->GetArchitecture();
	if (!arch)
		return result;

	BNFirmwareNinjaFunctionMemoryAccesses** fmaArray = MemoryInfoVectorToArray(fma);
	BNFirmwareNinjaDeviceAccesses* accesses;
	int count = BNFirmwareNinjaGetBoardDeviceAccesses(m_object, fmaArray, fma.size(), &accesses, arch->GetObject());
	FreeMemoryInfoArray(fmaArray, fma.size());
	if (count <= 0)
		return result;

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back({accesses[i].name, accesses[i].total, accesses[i].unique});

	BNFirmwareNinjaFreeBoardDeviceAccesses(accesses, count);
	sort(result.begin(), result.end(), [](const FirmwareNinjaDeviceAccesses& a, const FirmwareNinjaDeviceAccesses& b) {
		return a.total > b.total;
	});

	return result;
}


Ref<FirmwareNinjaReferenceNode> FirmwareNinja::GetReferenceTree(
	FirmwareNinjaDevice& device, const std::vector<FirmwareNinjaFunctionMemoryAccesses>& fma, uint64_t* value)
{
	BNFirmwareNinjaFunctionMemoryAccesses** fmaArray = nullptr;
	if (!fma.empty())
		fmaArray = MemoryInfoVectorToArray(fma);

	auto bnReferenceTree = BNFirmwareNinjaGetMemoryRegionReferenceTree(
		m_object, device.start, device.end, fmaArray, fma.size(), value);

	FreeMemoryInfoArray(fmaArray, fma.size());
	if (!bnReferenceTree)
		return nullptr;

	return new FirmwareNinjaReferenceNode(BNNewFirmwareNinjaReferenceNodeReference(bnReferenceTree));
}


Ref<FirmwareNinjaReferenceNode> FirmwareNinja::GetReferenceTree(
	Section& section, const std::vector<FirmwareNinjaFunctionMemoryAccesses>& fma, uint64_t* value)
{
	BNFirmwareNinjaFunctionMemoryAccesses** fmaArray = nullptr;
	if (!fma.empty())
		fmaArray = MemoryInfoVectorToArray(fma);

	auto bnReferenceTree = BNFirmwareNinjaGetMemoryRegionReferenceTree(
		m_object, section.GetStart(), section.GetStart() + section.GetLength(), fmaArray, fma.size(), value);

	FreeMemoryInfoArray(fmaArray, fma.size());
	if (!bnReferenceTree)
		return nullptr;

	return new FirmwareNinjaReferenceNode(BNNewFirmwareNinjaReferenceNodeReference(bnReferenceTree));
}


Ref<FirmwareNinjaReferenceNode> FirmwareNinja::GetReferenceTree(
	uint64_t address, const std::vector<FirmwareNinjaFunctionMemoryAccesses>& fma, uint64_t* value)
{
	BNFirmwareNinjaFunctionMemoryAccesses** fmaArray = nullptr;
	if (!fma.empty())
		fmaArray = MemoryInfoVectorToArray(fma);

	auto bnReferenceTree = BNFirmwareNinjaGetAddressReferenceTree(m_object, address, fmaArray, fma.size(), value);

	FreeMemoryInfoArray(fmaArray, fma.size());
	if (!bnReferenceTree)
		return nullptr;

	return new FirmwareNinjaReferenceNode(BNNewFirmwareNinjaReferenceNodeReference(bnReferenceTree));
}


std::vector<Ref<FirmwareNinjaRelationship>> FirmwareNinja::QueryRelationships()
{
	std::vector<Ref<FirmwareNinjaRelationship>> result;
	size_t count = 0;
	auto bnRelationships = BNFirmwareNinjaQueryRelationships(m_object, &count);
	result.reserve(count);
	for (size_t i = 0; i < count; ++i)
	{
		result.push_back(new FirmwareNinjaRelationship(m_view,
			BNNewFirmwareNinjaRelationshipReference(bnRelationships[i])));
	}

	return result;
}


void FirmwareNinja::AddRelationship(Ref<FirmwareNinjaRelationship> relationship)
{
	BNFirmwareNinjaAddRelationship(m_object, relationship->GetObject());
}


Ref<FirmwareNinjaRelationship> FirmwareNinja::GetRelationshipByGuid(const std::string& guid)
{
	auto bnRelationship = BNFirmwareNinjaGetRelationshipByGuid(m_object, guid.c_str());
	if (!bnRelationship)
		return nullptr;

	return new FirmwareNinjaRelationship(m_view, BNNewFirmwareNinjaRelationshipReference(bnRelationship));
}


void FirmwareNinja::RemoveRelationshipByGuid(const std::string& guid)
{
	BNFirmwareNinjaRemoveRelationshipByGuid(m_object, guid.c_str());
}
