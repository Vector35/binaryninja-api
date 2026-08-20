#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <vector>

#include "binaryninjaapi.h"
#include "SharedCache.h"

namespace BinaryNinja::DSC {

	// A string found in the cache by `CacheStringScanner`.
	struct CacheString
	{
		BNStringType type;
		uint64_t address;
		// Length of the string in the cache, in bytes.
		size_t rawLength;
		// UTF-8 display text, truncated to `CacheStringScanner::kMaxDisplayTextLength` bytes.
		std::string text;
		// Start address of the region containing the string.
		uint64_t regionStart;
		// Header address of the image owning the region, or 0 if the region is not part of an image.
		uint64_t imageStart;
	};

	// Scans all mapped cache regions for strings using the same string detection as the core
	// strings analysis. Each region is scanned as a separate worker pool job. Results queue in job
	// completion order. Consumers drain them with `TakeStrings(maxCount)`, so the scanner only
	// holds strings that have not yet been handed off. Sort once the scan completes.
	class CacheStringScanner
	{
	public:
		static constexpr size_t kMaxDisplayTextLength = 256;

		CacheStringScanner(SharedCache& cache, std::regex regionFilter, Ref<Logger> logger);
		~CacheStringScanner();

		CacheStringScanner(const CacheStringScanner&) = delete;
		CacheStringScanner& operator=(const CacheStringScanner&) = delete;

		// Enqueues a scan job for each cache region. Idempotent.
		// Returns false if the scan was already started.
		bool Start();

		bool IsScanStarted() const { return m_started.load(); }
		bool IsScanComplete() const { return m_state && m_state->complete.load(); }

		// Progress in bytes scanned out of total bytes scheduled for scanning.
		void GetProgress(uint64_t& current, uint64_t& total) const;

		// Total number of strings detected so far, including those already taken.
		size_t GetStringCount() const;

		// Removes and returns up to `maxCount` of the queued strings. Result order is unspecified.
		std::vector<CacheString> TakeStrings(size_t maxCount);

	private:
		// Everything the scan jobs read and write, owned jointly by the scanner and every queued
		// job so that the scanner itself can safely be destroyed while jobs are still queued or
		// running.
		struct ScanState
		{
			std::shared_ptr<VirtualMemory> vm;
			// The regions to scan, copied out of the cache so the jobs do not reference it.
			std::vector<CacheRegion> regions;
			Ref<Logger> logger;
			std::optional<StringDetector> detector;

			std::atomic<bool> complete = false;
			std::atomic<bool> abort = false;

			std::mutex completionMutex;
			size_t remainingRegions = 0;

			std::atomic<uint64_t> bytesScanned = 0;
			std::atomic<uint64_t> bytesTotal = 0;

			std::mutex resultsMutex;
			// Detected strings not yet taken. TakeStrings drains from the back, which is O(1) per
			// element. Order does not matter as the consumer sorts the full set once scanning
			// completes.
			std::vector<CacheString> strings;
			// Total detected, including taken strings. Not reduced by TakeStrings.
			uint64_t producedCount = 0;
		};

		static void ScanRegion(ScanState& state, const CacheRegion& region);
		static void FinishRegion(ScanState& state);

		// Used only by `Start`, which copies the scan inputs into `ScanState`.
		SharedCache& m_cache;
		std::regex m_regionFilter;
		Ref<Logger> m_logger;

		std::atomic<bool> m_started = false;
		std::shared_ptr<ScanState> m_state;
	};

}  // namespace BinaryNinja::DSC
