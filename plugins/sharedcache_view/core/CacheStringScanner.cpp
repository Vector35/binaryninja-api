#include "CacheStringScanner.h"

#include "base/unicode.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace BinaryNinja::DSC;

namespace {

constexpr size_t kChunkSize = 1024 * 1024;

// Builds the UTF-8 display text for a string found at `data`, truncated to
// `CacheStringScanner::kMaxDisplayTextLength` bytes of output.
std::string DisplayTextForString(const uint8_t* data, const BNStringReference& ref)
{
	constexpr size_t maxLength = CacheStringScanner::kMaxDisplayTextLength;
	const std::span bytes(data, ref.length);
	switch (ref.type)
	{
	case AsciiString:
	case Utf8String:
		return bn::base::TruncateUTF8<std::string>(bytes, maxLength);
	case Utf16String:
		return bn::base::UTF16ToUTF8<std::string>(bytes, maxLength);
	case Utf32String:
		return bn::base::UTF32ToUTF8<std::string>(bytes, maxLength);
	}
	return {};
}

}  // namespace

CacheStringScanner::CacheStringScanner(SharedCache& cache, std::regex regionFilter, Ref<Logger> logger)
	: m_cache(cache), m_regionFilter(std::move(regionFilter)), m_logger(std::move(logger))
{}

CacheStringScanner::~CacheStringScanner()
{
	// Tell any outstanding scan jobs to bail out. We cannot block waiting for them to
	// drain as it would risk a deadlock during exit.
	if (m_state)
		m_state->abort = true;
}

bool CacheStringScanner::Start()
{
	if (m_started.exchange(true))
		return false;

	auto state = std::make_shared<ScanState>();
	state->vm = m_cache.GetVirtualMemory();
	state->logger = m_logger;
	state->detector.emplace(StringDetectionParameters::FromSettings(Settings::Instance()));

	uint64_t totalBytes = 0;
	for (const auto& [range, region] : m_cache.GetRegions())
	{
		// Stub islands hold only trampoline code, and the filtered regions (LINKEDIT by default)
		// hold symbol tables whose name strings are already presented by the symbols UI.
		if (region.type == CacheRegionType::StubIsland)
			continue;
		if (std::regex_match(region.name, m_regionFilter))
			continue;
		state->regions.push_back(region);
		totalBytes += region.size;
	}
	state->bytesTotal = totalBytes;
	m_state = state;

	if (state->regions.empty())
	{
		state->complete = true;
		return true;
	}

	{
		std::lock_guard lock(state->completionMutex);
		state->remainingRegions = state->regions.size();
	}
	for (size_t i = 0; i < state->regions.size(); i++)
	{
		// Scanning starts only when the user opens the Strings tab and is watching it fill, so it
		// runs at priority above the normal-priority background analysis of off-screen code.
		WorkerPriorityEnqueue([state, i] {
			ScanRegion(*state, state->regions[i]);
			FinishRegion(*state);
		}, "Scanning shared cache strings");
	}
	return true;
}

void CacheStringScanner::FinishRegion(ScanState& state)
{
	std::lock_guard lock(state.completionMutex);
	if (--state.remainingRegions == 0)
		state.complete = true;
}

void CacheStringScanner::GetProgress(uint64_t& current, uint64_t& total) const
{
	if (!m_state)
	{
		current = 0;
		total = 0;
		return;
	}
	current = m_state->bytesScanned.load();
	total = m_state->bytesTotal.load();
}

size_t CacheStringScanner::GetStringCount() const
{
	if (!m_state)
		return 0;
	std::lock_guard lock(m_state->resultsMutex);
	return m_state->producedCount;
}

std::vector<CacheString> CacheStringScanner::TakeStrings(size_t maxCount)
{
	if (!m_state)
		return {};
	auto& strings = m_state->strings;
	std::lock_guard lock(m_state->resultsMutex);
	const size_t count = std::min(maxCount, strings.size());
	const size_t first = strings.size() - count;
	std::vector<CacheString> result(
		std::make_move_iterator(strings.begin() + first), std::make_move_iterator(strings.end()));
	strings.erase(strings.begin() + first, strings.end());

	// Shrink the buffer if it both proportionally and substantially larger than the live data.
	static constexpr size_t kMinReclaimableSlack = 1 << 20;
	if (strings.capacity() > 2 * strings.size() + kMinReclaimableSlack)
		strings.shrink_to_fit();

	return result;
}

void CacheStringScanner::ScanRegion(ScanState& state, const CacheRegion& region)
{
	const uint64_t imageStart = region.imageStart.value_or(0);
	const uint64_t end = region.start + region.size;

	BNStringReference lastFound {};
	for (uint64_t cur = region.start; cur < end; )
	{
		if (state.abort)
			return;

		const size_t blockLen = static_cast<size_t>(std::min<uint64_t>(kChunkSize, end - cur));
		const size_t dataLen = static_cast<size_t>(std::min<uint64_t>(blockLen + BN_MAX_STRING_LENGTH, end - cur));

		std::span<const uint8_t> data;
		try
		{
			data = state.vm->ReadSpan(cur, dataLen);
		}
		catch (std::exception& e)
		{
			// This happens if we have not mapped in all the relevant entries.
			state.logger->LogErrorF("Failed to read region {:#x} while scanning for strings: {}", region.start, e.what());
			state.bytesScanned += end - cur;
			return;
		}

		const auto refs = state.detector->DetectStrings(data.data(), dataLen, blockLen, cur, &lastFound);

		std::vector<CacheString> batch;
		batch.reserve(refs.size());
		for (const auto& ref : refs)
		{
			CacheString str;
			str.type = ref.type;
			str.address = ref.start;
			str.rawLength = ref.length;
			str.text = DisplayTextForString(data.data() + (ref.start - cur), ref);
			str.regionStart = region.start;
			str.imageStart = imageStart;
			batch.push_back(std::move(str));
		}

		{
			std::lock_guard lock(state.resultsMutex);
			state.producedCount += batch.size();
			state.strings.insert(state.strings.end(), std::make_move_iterator(batch.begin()),
				std::make_move_iterator(batch.end()));
		}

		state.bytesScanned += blockLen;
		cur += blockLen;
	}
}
