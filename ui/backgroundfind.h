#pragma once

#include <QtCore/QObject>
#include <QtCore/QPointer>
#include <QtCore/QThread>
#include <QtCore/QTimer>
#include <chrono>
#include <memory>
#include <optional>
#include <stddef.h>
#include <stdint.h>
#include <vector>
#include "binaryninjaapi.h"
#include "uitypes.h"

class View;

/*!

	\defgroup backgroundfind BackgroundFind
	\ingroup uiapi
*/

/*!
    \ingroup backgroundfind
*/
struct FindMatch
{
	uint64_t address;
	BinaryNinja::DataBuffer data;
	std::optional<BinaryNinja::LinearDisassemblyLine> line;
	// The index into the search's ranges of the range that holds the match.
	size_t rangeIndex;
};

/*!
    \ingroup backgroundfind
*/
struct FindUpdate
{
	// The matches found since the previous update.
	std::vector<FindMatch> matches;
	uint64_t progress = 0;
	uint64_t total = 0;
	bool finished = false;
};

/*!
    A Find Next or Find All that runs on a background thread.

    \ingroup backgroundfind
*/
class BINARYNINJAUIAPI BackgroundFind : public QObject
{
	Q_OBJECT

	struct State;

  public:
	struct Deleter
	{
		void operator()(BackgroundFind* search) const;
	};

	// Releasing this pointer cancels the search.
	using Ptr = std::unique_ptr<BackgroundFind, Deleter>;

	// How often `updated` is emitted while the search runs.
	static constexpr std::chrono::milliseconds UpdateInterval {250};

  private:
	// Shared with the thread that runs the search, which never refers to the `BackgroundFind` or its owner.
	std::shared_ptr<State> m_state;
	QPointer<QThread> m_thread;
	QTimer m_timer;
	bool m_finished = false;

	explicit BackgroundFind(std::shared_ptr<State> state);
	static Ptr start(std::shared_ptr<State> state);
	void poll();
	// Stops the search and its updates without deleting the `BackgroundFind`.
	void cancel();

  public:
	// Searches `ranges` in order and stops at the first match.
	static Ptr startFindNext(BinaryViewRef data, const BinaryNinja::FindParameters& params,
		DisassemblySettingsRef settings, std::vector<BNAddressRange> ranges);
	// Searches `params.ranges` for every match.
	static Ptr startFindAll(
		BinaryViewRef data, const BinaryNinja::FindParameters& params, DisassemblySettingsRef settings);

	// The settings that Find renders lines with, derived from those of `view`.
	static DisassemblySettingsRef settingsFor(View* view);
	// Cancels every running search and waits for their threads to exit.
	static void cancelAllAndWait();

	// Returns the progress and the matches found since the previous call. An update with `finished` set is the last.
	FindUpdate takeUpdate();

  Q_SIGNALS:
	// Emitted every `UpdateInterval` while the search runs, and once after it finishes.
	void updated();
};


inline void BackgroundFind::Deleter::operator()(BackgroundFind* search) const
{
	search->cancel();
	// A slot connected to `updated` may release the `Ptr` while the signal is being emitted, so the deletion waits for
	// the event loop.
	search->deleteLater();
}
