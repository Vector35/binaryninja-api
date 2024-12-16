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
	auto platform = m_view->GetDefaultPlatform();
	if (!platform)
		return result;

	auto arch = platform->GetArchitecture();
	if (!arch)
		return result;

	BNFirmwareNinjaFunctionMemoryAccesses** fmaArray = MemoryInfoVectorToArray(fma);
	BNFirmwareNinjaDeviceAccesses* accesses;
	int count = BNFirmwareNinjaGetBoardDeviceAccesses(m_object, fmaArray, fma.size(), &accesses, arch->GetObject());
	if (count <= 0)
	{
		FreeMemoryInfoArray(fmaArray, fma.size());
		return result;
	}

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back({accesses[i].name, accesses[i].total, accesses[i].unique});

	BNFirmwareNinjaFreeBoardDeviceAccesses(accesses, count);
	sort(result.begin(), result.end(), [](const FirmwareNinjaDeviceAccesses& a, const FirmwareNinjaDeviceAccesses& b) {
		return a.total > b.total;
	});

	return result;
}
