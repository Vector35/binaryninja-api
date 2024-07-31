#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace BinaryNinja
{
	class BinaryView;


	struct BaseAddressDetectionSettings
	{
		std::string Architecture;
		std::string Analysis;
		uint32_t MinStrlen;
		uint32_t Alignment;
		uint64_t LowerBoundary;
		uint64_t UpperBoundary;
		BNBaseAddressDetectionPOISetting POIAnalysis;
		uint32_t MaxPointersPerCluster;
	};

	/*!
		\ingroup baseaddressdetection
	*/
	class BaseAddressDetection
	{
		BNBaseAddressDetection* m_object;

	public:
		BaseAddressDetection(Ref<BinaryView> view);
		~BaseAddressDetection();

		/*! Analyze program, identify pointers and points-of-interest, and detect candidate base addresses

			\param settings Base address detection settings
			\return true on success, false otherwise
		 */
		bool DetectBaseAddress(BaseAddressDetectionSettings& settings);

		/*! Get the top 10 candidate base addresses and thier scores

			\param confidence Confidence level that indicates the likelihood the top base address candidate is correct
			\param lastTestedBaseAddress Last base address tested before analysis was aborted or completed
			\return Set of pairs containing candidate base addresses and their scores
		 */
		std::set<std::pair<size_t, uint64_t>> GetScores(BNBaseAddressDetectionConfidence* confidence, uint64_t *lastTestedBaseAddress);

		/*! Get a vector of BNBaseAddressDetectionReasons containing information that indicates why a base address was reported as a candidate

			\param baseAddress Base address to query reasons for
			\return Vector of reason structures containing information about why a base address was reported as a candidate
		 */
		std::vector<BNBaseAddressDetectionReason> GetReasonsForBaseAddress(uint64_t baseAddress);

		/*! Abort base address detection
		 */
		void Abort();

		/*! Determine if base address detection is aborted

			\return true if aborted by user, false otherwise
		 */
		bool IsAborted();
	};
}
