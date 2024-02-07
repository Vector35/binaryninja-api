#pragma once

#include <QtCore/QObject>
#include <QtCore/QThread>
#include <QtCore/QVariant>
#include <QtCore/QCoreApplication>
#include <QtGui/QKeyEvent>
#include <QtConcurrent/QtConcurrent>
#include <QtWidgets/QBoxLayout>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QPushButton>
#include <atomic>
#include <functional>
#include <chrono>
#include <deque>
#include "binaryninjaapi.h"
#include "uitypes.h"

/*!

	\defgroup progresstask ProgressTask
 	\ingroup uiapi
*/

/*!

	\defgroup backgroundthread BackgroundThread
 	\ingroup uiapi
*/

/*!
    Dialog displaying a progress bar and cancel button

    \ingroup progresstask
 */
class BINARYNINJAUIAPI ProgressDialog : public QDialog
{
	Q_OBJECT

	QProgressBar* m_progress;
	QLabel* m_text;
	QPushButton* m_cancel;
	bool m_cancellable;
	bool m_maxSet;
	std::atomic<bool> m_processing;
	std::atomic<bool> m_wasCancelled;
	std::chrono::steady_clock::time_point m_lastUpdate;

  public:
	ProgressDialog(QWidget* parent, const QString& title, const QString& text, const QString& cancel = QString());

	bool wasCancelled() const;

	void hideForModal(std::function<void()> modal);

	QString text() const;

	void setText(const QString& text);

  protected:
	virtual void keyPressEvent(QKeyEvent* event) override;

  private Q_SLOTS:
	void cancelButton();

  public Q_SLOTS:
	void update(int cur, int total);

	void cancel();
  Q_SIGNALS:
	void canceled();
};


/*!
    Wrapper around QThread and ProgressDialog that runs a task in the background,
    providing updates to the progress bar on the main thread.

    \warning You should always construct one of these with new() as it will outlive the current
    scope and delete itself automatically.

    Started automatically. Call wait() to wait for completion, or cancel() to cancel.

    \b Example:

 	\code{.cpp}
	// Starts task
	ProgressTask* task = new ProgressTask("Long Operation", "Long Operation", "Cancel",
		[](std::function<bool(size_t, size_t)> progress) {
			doLongOperationWithProgress(progress);

			// Report progress by calling the progress function
			if (!progress(current, maximum))
				return; // If the progress function returns false, then the user has cancelled the operation
		});
	// Throws if doLongOperationWithProgress threw
	task->wait();
	// Task deletes itself later
 	\endcode

 	\ingroup progresstask
 */
class BINARYNINJAUIAPI ProgressTask : public QObject
{
	Q_OBJECT

	ProgressDialog* m_dialog;
	std::function<void(std::function<bool(size_t, size_t)>)> m_func;
	std::thread m_thread;
	std::mutex m_mutex;
	std::condition_variable m_cv;
	bool m_canceled;
	bool m_finished;

	std::exception_ptr m_exception;

	/*!
	    Run the task function (called on the background thread)
	 */
	void start();

  public:
	/*!
	    Construct a new progress task, which automatically starts running a given function
	    \param parent Parent QWidget to display progress dialog on top of
	    \param name Title for progress dialog
	    \param text Text for progress dialog
	    \param cancel Cancel button title. If empty, the cancel button will not be shown
	    \param func Function to run in the background, which takes a progress reporting function for its argument.
	                The function should call the progress function periodically to signal updates and check for
	   cancellation.
	 */
	ProgressTask(QWidget* parent, const QString& name, const QString& text, const QString& cancel,
	    std::function<void(std::function<bool(size_t, size_t)>)> func);
	virtual ~ProgressTask();

	/*!
	    Wait for the task to finish
	    \throws exception Any exception that the provided func throws
	    \returns False if canceled, true otherwise
	 */
	bool wait();

	/*!
	    Hide the task to present a modal (in a function) since the progress dialog will block other parts of
	    the ui from responding while it is present.
	    \param modal Function to present a modal ui on top
	 */
	void hideForModal(std::function<void()> modal);

	/*!
	    Get the text label of the progress dialog
	    \return Text label contents
	 */
	QString text() const;

	/*!
	    Set the text label on the progress dialog
	    \param text New text label contents
	 */
	void setText(const QString& text);

  public Q_SLOTS:
	/*!
	    Cancel the progress dialog
	 */
	void cancel();

  Q_SIGNALS:
	/*!
	    Signal reported every time there is a progress update (probably often)
	    \param cur Current progress value
	    \param max Maximum progress value
	 */
	void progress(int cur, int max);

	/*!
	    Signal reported when the task has finished
	 */
	void finished();
};


/*!
    Helper for BackgroundThread, basically lets you take functions of various types and converts them into
    std::function<QVariant(QVariant)> so it has something easy to call.

    \param func Original function, can have 0 arguments, or 1 argument that can be used with QVariant,
                function can either return void or some type that works with QVariant
    \return New function whose signature is QVariant(QVariant)
 */
template <typename Func>
std::function<QVariant(QVariant)> convertToQVariantFunction(Func&& func);


/*! Helper class for running chains of actions on both the main thread and a background thread.
    Especially useful for doing ui that also needs networking.
    Think of it like a JS-like promise chain except with more C++.

    \b Example:
    \code{.cpp}
        // Passing `this` into create() will make the thread stop if `this` is deleted before it finishes.
        BackgroundThread::create(this)
        // Do actions serially in the background
        ->thenBackground([this](QVariant) {
            bool success = SomeLongNetworkOperation();
            // Return value will be passed to next action's QVariant parameter
            return success;
        })
        // And serially on the main thread
        ->thenMainThread([this](QVariant var) {
            // Retrieve value from last action
            bool success = var.value<bool>();
            UpdateUI(success);
            // You don't have to return anything (next QVariant param will be QVariant())
        })
        // You can also combine with a ProgressTask for showing a progress dialog
        ->thenBackgroundWithProgress(m_window, "Doing Task", "Please wait...", "Cancel", [this](QVariant var,
   ProgressTask* task, ProgressFunction progress) {
            progress(0, 0);
            DoTask1WithProgress(SplitProgress(progress, 0, 1));
            // You can interface with the task itself
            task->setText("Doing Part 2");
            DoTask2WithProgress(SplitProgress(progress, 1, 1));
            progress(1, 1);
        })
        // You can combine with another BackgroundThread to do its actions after all of the
        // ones you have enqueued so far
        ->then(SomeOtherFunctionThatReturnsABackgroundThread())
        // If any then-action throws, all future then-actions will be ignored and the catch-actions will be run,
   serially
        // NB: If a catch-action throws, the new exception will be passed to any further catch-actions
        ->catchMainThread([this](std::exception_ptr exc) {
            // So far the only way I've found to get the exception out:
            try
            {
                std::rethrow_exception(exc);
            }
            catch (std::exception e)
            {
                // Handle exception
            }
        })
        // You can also catch in the background
        ->catchBackground([this](std::exception_ptr exc) {
            ...
        })
        // Finally-actions will be run after all then-actions are finished
        // If a then-action throws, finally-actions will be run after all catch-actions are finished
        // NB: Finally-actions should not throw exceptions
        ->finallyMainThread([this](bool success) {
            if (success)
            {
                ReportSuccess();
            }
        })
        // You can also have finally-actions in the background
        ->finallyBackground([this](bool success) {
            ...
        })
        // Call start to start the thread
        ->start();
    \endcode

    \ingroup backgroundthread
 */
class BINARYNINJAUIAPI BackgroundThread : public QObject
{
	Q_OBJECT

  public:
	typedef std::function<bool(size_t, size_t)> ProgressFunction;

	typedef std::function<QVariant(QVariant value)> ThenFunction;
	typedef std::function<void(std::exception_ptr exc)> CatchFunction;
	typedef std::function<void(bool success) /* noexcept */> FinallyFunction;

  private:
	enum FunctionType
	{
		MainThread,
		Background
	};

	QPointer<QObject> m_owner;
	bool m_hasOwner;
	QVariant m_init;
	QFuture<void> m_future;
	bool m_finished;
	std::recursive_mutex m_finishLock;
	std::exception_ptr m_exception;
	std::deque<std::pair<FunctionType, ThenFunction>> m_then;
	std::deque<std::pair<FunctionType, CatchFunction>> m_catch;
	std::deque<std::pair<FunctionType, FinallyFunction>> m_finally;

	BackgroundThread(QObject* owner) : QObject(), m_owner(owner), m_hasOwner(owner != nullptr), m_finished(false), m_exception() {}

	void runThread()
	{
		QVariant value = m_init;
		try
		{
			for (auto& func : m_then)
			{
				if (m_hasOwner && m_owner.isNull())
					return;
				switch (func.first)
				{
				case MainThread:
					BinaryNinja::ExecuteOnMainThreadAndWait([&]() {
						if (m_hasOwner && m_owner.isNull())
							return;
						value = func.second(value);
					});
					break;
				case Background:
					value = func.second(value);
					break;
				}
			}
			for (auto& func : m_finally)
			{
				if (m_hasOwner && m_owner.isNull())
					return;
				try
				{
					switch (func.first)
					{
					case MainThread:
						BinaryNinja::ExecuteOnMainThreadAndWait([&]() {
							if (m_hasOwner && m_owner.isNull())
								return;
							func.second(true);
						});
						break;
					case Background:
						func.second(true);
						break;
					}
				}
				// Since we're already in the finally blocks, we can't reverse back to the catch blocks
				// Just print an error and keep going
				catch (std::exception& e)
				{
					BinaryNinja::LogError("Exception thrown in BackgroundThread::finally(): %s", e.what());
				}
				catch (...)
				{
					BinaryNinja::LogError("Exception thrown in BackgroundThread::finally()");
				}
			}
			triggerDone(value);
		}
		catch (...)
		{
			std::exception_ptr exc = std::current_exception();
			for (auto& func : m_catch)
			{
				if (m_hasOwner && m_owner.isNull())
					return;
				try
				{
					switch (func.first)
					{
					case MainThread:
						BinaryNinja::ExecuteOnMainThreadAndWait([&]() {
							if (m_hasOwner && m_owner.isNull())
								return;
							func.second(exc);
						});
						break;
					case Background:
						func.second(exc);
						break;
					}
				}
				catch (...)
				{
					exc = std::current_exception();
				}
			}
			for (auto& func : m_finally)
			{
				if (m_hasOwner && m_owner.isNull())
					return;
				try
				{
					switch (func.first)
					{
					case MainThread:
						BinaryNinja::ExecuteOnMainThreadAndWait([&]() {
							if (m_hasOwner && m_owner.isNull())
								return;
							func.second(false);
						});
						break;
					case Background:
						func.second(false);
						break;
					}
				}
				// Since we're already in the finally blocks, we can't reverse back to the catch blocks
				// Just print an error and keep going
				catch (std::exception& e)
				{
					BinaryNinja::LogError("Exception thrown in BackgroundThread::finally(): %s", e.what());
				}
				catch (...)
				{
					BinaryNinja::LogError("Exception thrown in BackgroundThread::finally()");
				}
			}
			triggerFail(exc);
		}
	}

	void triggerDone(QVariant result)
	{
		Q_EMIT done(result);
	}

	void triggerFail(std::exception_ptr exc)
	{
		Q_EMIT fail(exc);
	}

  public:
	/*!
	    Create a new background thread (but don't start it)
	    \param owner QObject that "owns" the thread (or nullptr). If this owner is destroyed, the thread will
	                 be terminated before the next callback.
	    \return Empty thread with no functions
	 */
	static BackgroundThread* create(QObject* owner = nullptr)
	{
		BackgroundThread* thread = new BackgroundThread(owner);
		return thread;
	}

	/*!
	    Start the thread and run all its functions in sequence.
	    \param init Argument for first function in the thread
	 */
	void start(QVariant init = QVariant())
	{
		if (!m_hasOwner || m_owner.isNull())
		{
			BinaryNinja::LogDebug("Starting background thread with no owning object. This is technically allowed but it might outlive any UIs it changes.");
		}
		if (m_then.empty() && m_catch.empty() && m_finally.empty())
		{
			std::unique_lock lock(m_finishLock);
			m_finished = true;
			deleteLater();
			return;
		}
		else
		{
			m_init = init;
			m_future = QtConcurrent::run([&] {
				runThread();
				{
					std::unique_lock lock(m_finishLock);
					m_finished = true;
				}
				deleteLater();
			});
		}
	}

	/*!
	    Block until the thread finishes
	 */
	void wait()
	{
		// Weird dance to make sure we don't race the thread finishing event
		QFutureWatcher<void> watcher;
		QEventLoop loop;
		{
			std::unique_lock lock(m_finishLock);
			// If it's already finished, return early
			if (m_finished)
				return;
			// If it's not finished, wait for it to finish
			watcher.setFuture(m_future);
			// Make this connection before events start processing
			connect(&watcher, &QFutureWatcher<void>::finished, [&loop]() { loop.exit(0); });
		}
		loop.exec();
	}

	/*!
	    Add another BackgroundThread's functions to the end of this one's. Will move functions out of `other`
	    \param other BackgroundThread whose functions will be used
	    \return This BackgroundThread
	 */
	BackgroundThread* then(BackgroundThread* other)
	{
		std::move(other->m_then.begin(), other->m_then.end(), std::back_inserter(m_then));
		std::move(other->m_catch.begin(), other->m_catch.end(), std::back_inserter(m_catch));
		// Push finally actions in reverse so the child task is finished before running the parent's finallys
		std::deque<std::pair<FunctionType, FinallyFunction>> finally;
		std::move(other->m_finally.begin(), other->m_finally.end(), std::back_inserter(finally));
		std::move(m_finally.begin(), m_finally.end(), std::back_inserter(finally));
		m_finally = std::move(finally);

		// Connect our done signal to their done signal
		connect(this, &BackgroundThread::done, other, [other](QVariant result) {
			other->triggerDone(result);
		});
		connect(this, &BackgroundThread::fail, other, [other](std::exception_ptr exc) {
			other->triggerFail(exc);
		});

		return this;
	}

	/*!
	    Add a function to run on a background thread
	    \param func Function to run on background thread
	    \return This BackgroundThread
	 */
	template <typename Func>
	BackgroundThread* thenBackground(Func&& func)
	{
		m_then.push_back({Background, convertToQVariantFunction(std::forward<Func>(func))});
		return this;
	}

	/*!
	    Add a function to run on the main thread
	    \param func Function to run on main thread
	    \return This BackgroundThread
	 */
	template <typename Func>
	BackgroundThread* thenMainThread(Func&& func)
	{
		m_then.push_back({MainThread, convertToQVariantFunction(std::forward<Func>(func))});
		return this;
	}

	/*!
	    Add a function to run on a background thread, with a progress dialog that blocks the main thread while it runs
	    \param parent Parent widget for progress dialog
	    \param title Title of progress dialog
	    \param text Text of progress dialog
	    \param cancel Cancel button text for progress dialog
	    \param func Function to run on background thread, [QVariant|void](QVariant, ProgressTask*, ProgressFunction)
	    \return This BackgroundThread
	 */
	template <typename Func>
	BackgroundThread* thenBackgroundWithProgress(
	    QWidget* parent, const QString& title, const QString& text, const QString& cancel, Func&& func)
	{
		m_then.push_back(
			{MainThread, [=](QVariant v) {
				QVariant result;
				// Since the task starts immediately, we need to hold a lock to its value
				// Just in case it manages to get to the part of the lambda where it reads the value
				// before this thread actually assigns it.
				// This is *probably* not a race in practice due to the variable being stored on the stack before
				// construction.
				std::mutex taskMutex;
				taskMutex.lock();
				ProgressTask* task;
				task = new ProgressTask(parent, title, text, cancel, [&](ProgressFunction progress) {
					auto innerProgress = [=](size_t cur, size_t max) {
						// Fix dialog disappearing if the backgrounded task thinks it's done
						if (cur >= max)
						{
							cur = max - 1;
						}
						return progress(cur, max);
					};
					try
					{
						// See above comment about race conditions
						taskMutex.lock();
						ProgressTask* innerTask = task;
						taskMutex.unlock();

						if constexpr (std::is_void_v<
						              std::invoke_result_t<Func, QVariant, ProgressTask*, ProgressFunction>>)
						{
							func(v, innerTask, innerProgress);
						}
						else
						{
							result = func(v, innerTask, innerProgress);
						}
						// And actually report success
						progress(1, 1);
					}
					catch (...)
					{
						progress(1, 1);
						std::rethrow_exception(std::current_exception());
					};
				});
				taskMutex.unlock();
				task->wait();

				return result;
			}});
		return this;
	}

	/*!
	    Add a function to run on a background thread in the event an exception is thrown
	    \param func Function to run on background thread
	    \return This BackgroundThread
	 */
	BackgroundThread* catchBackground(CatchFunction func)
	{
		m_catch.push_back({Background, func});
		return this;
	}

	/*!
	    Add a function to run on the main thread in the event an exception is thrown
	    \param func Function to run on main thread
	    \return This BackgroundThread
	 */
	BackgroundThread* catchMainThread(CatchFunction func)
	{
		m_catch.push_back({MainThread, func});
		return this;
	}

	/*!
	    Add a function to run on a background thread after all other functions, even if something threw
	    \param func Function to run on background thread
	    \return This BackgroundThread
	 */
	BackgroundThread* finallyBackground(FinallyFunction func)
	{
		m_finally.push_back({Background, func});
		return this;
	}

	/*!
	    Add a function to run on the main thread after all other functions, even if something threw
	    \param func Function to run on main thread
	    \return This BackgroundThread
	 */
	BackgroundThread* finallyMainThread(FinallyFunction func)
	{
		m_finally.push_back({MainThread, func});
		return this;
	}

  Q_SIGNALS:
	/*!
	    Called when all functions have been run
	    \param result Final result
	 */
	void done(QVariant result);

	/*!
	    Called when an exception is thrown, after all catch functions have been run
	    \param exception Thrown exception
	 */
	void fail(std::exception_ptr exception);
};


// Implementation details of convertToQVariantFunction
// Inspired by boost function_traits and various other similarly named patterns
template <typename Function>
struct function_traits;
template <typename Function>
struct function_traits : public function_traits<decltype(&Function::operator())>
{};
template <typename C, typename R, typename... Args>
struct function_traits<R (C::*)(Args...) const>
{
	using result_type = R;
	template <size_t index>
	using arg_type = typename std::tuple_element_t<index, std::tuple<Args...>>;
	static const size_t arity = sizeof...(Args);
};

template <typename Func>
std::function<QVariant(QVariant)> convertToQVariantFunction(Func&& func)
{
	return [func](QVariant v) {
		if constexpr (function_traits<Func>::arity == 0)
		{
			if constexpr (std::is_void_v<typename function_traits<Func>::result_type>)
			{
				func();
				return QVariant();
			}
			else
			{
				return func();
			}
		}
		else if constexpr (!std::is_same_v<typename function_traits<Func>::template arg_type<0>, QVariant>)
		{
			if constexpr (std::is_void_v<typename function_traits<Func>::result_type>)
			{
				func(v.template value<typename function_traits<Func>::template arg_type<0>>());
				return QVariant();
			}
			else
			{
				return func(v.template value<typename function_traits<Func>::template arg_type<0>>());
			}
		}
		else
		{
			if constexpr (std::is_void_v<typename function_traits<Func>::result_type>)
			{
				func(v);
				return QVariant();
			}
			else
			{
				return func(v);
			}
		}
	};
}
