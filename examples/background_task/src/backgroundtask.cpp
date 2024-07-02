#include <thread>
#include <random>

#include "binaryninjaapi.h"

using namespace BinaryNinja;

static Ref<BackgroundTask> inspireBackgroundTask = nullptr;

uint64_t InspireWriteCallback(uint8_t *data, uint64_t len, void *ctxt)
{
	try
	{
		Json::Value json;
		std::unique_ptr<Json::CharReader> reader(Json::CharReaderBuilder().newCharReader());
		std::string errors;
		if (!reader->parse((char *) data, (char *) data + len, &json, &errors))
		{
			LogError("Failed to parse! %s", errors.c_str());
		}
		else
		{
			std::random_device rd;
			std::map<int, int> hist;
			std::uniform_int_distribution<Json::ArrayIndex> dist(0, json.size());
			auto randQuoteObj = json.get(dist(rd), 0);
			if (randQuoteObj.isObject() && randQuoteObj.size() == 2)
			{
				std::string quote = randQuoteObj.get("text", Json::Value("INVALID")).asString();
				LogInfo("%s", quote.c_str());
				// Display quote in progress text for 3 seconds.
				inspireBackgroundTask->SetProgressText(quote);
				std::this_thread::sleep_for(std::chrono::seconds(3));
			}
		}
	} catch (Json::Exception e)
	{
		LogError("JSON exception! %s", e.m_message.c_str());
		inspireBackgroundTask->Cancel();
	}
	return len;
}

bool InspireProgressCallback(void *ctxt, uint64_t progress, uint64_t total)
{
	// Close connection on cancellation
	return !inspireBackgroundTask->IsCancelled();
}

void Inspire(BinaryView *bv)
{
	inspireBackgroundTask = new BackgroundTask("Getting inspired!", true);
	std::thread inspireThread([]() {
		LogInfo("Getting inspired!");
		BNDownloadInstanceOutputCallbacks outputCallbacks;
		memset(&outputCallbacks, 0, sizeof(outputCallbacks));
		outputCallbacks.writeCallback = InspireWriteCallback;
		outputCallbacks.progressCallback = InspireProgressCallback;

		auto downloadProvider = DownloadProvider::GetByName("CoreDownloadProvider");
		auto downloadInstance = downloadProvider->CreateNewInstance();
		inspireBackgroundTask->SetProgressText("Waiting for inspiration...");
		if (downloadInstance->PerformRequest("https://type.fit/api/quotes", &outputCallbacks))
			LogError("Inspiration failed!");

		inspireBackgroundTask->Finish();
	});
	inspireThread.detach();
}

extern "C" {
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		PluginCommand::Register("Inspire me!", "Print an inspirational quote to the log", Inspire);

		return true;
	}
}
