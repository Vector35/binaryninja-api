#pragma once

#include <QtCore/QTimer>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QWidget>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
#include "binaryninjaapi.h"
#include "action.h"
#include "dockhandler.h"
#include "uitypes.h"

#define SCRIPT_OUTPUT_UPDATE_INTERVAL 100
#define SCRIPT_HISTORY_LENGTH 100

class ScriptingConsole;

class BINARYNINJAUIAPI ScriptingConsoleEdit: public QTextEdit
{
	Q_OBJECT

	ScriptingConsole* m_console;
	int m_charHeight;
	bool m_continuation;

public:
	ScriptingConsoleEdit(ScriptingConsole* parent);
	void setCharHeight(int height);
	void setContinutation(bool cont);

protected:
	virtual void keyPressEvent(QKeyEvent* event) override;
};

class BINARYNINJAUIAPI ScriptingConsoleOutput: public QTextEdit
{
	Q_OBJECT

	ScriptingConsole* m_console;
	QAction* m_outputActionClear;

public:
	ScriptingConsoleOutput(ScriptingConsole* parent);

protected:
	virtual void contextMenuEvent(QContextMenuEvent *event) override;
};

class ScriptingConsoleWidget;

class BINARYNINJAUIAPI ScriptingConsole: public QWidget, public DockContextHandler, BinaryNinja::ScriptingOutputListener
{
	Q_OBJECT

	struct ScriptOutput
	{
		std::string text;
		bool isError;
	};

	QString m_providerName;
	QString m_instanceName;
	ScriptingInstanceRef m_instance;
	ScriptingConsoleOutput* m_output;
	ScriptingConsoleEdit* m_input;
	QLabel* m_prompt;
	QPushButton* m_button;
	QTimer* m_runTimer;

	std::mutex m_mutex;
	std::vector<ScriptOutput> m_pendingOutput;
	QTimer* m_updateTimer;

	BNScriptingProviderInputReadyState m_currentState;

	QStringList m_history;
	QString m_inputOutsideHistory;
	int m_currentHistoryEntry;

	static int m_stateUpdatedEventType;

private Q_SLOTS:
	void updateTimerEvent();
	void cancel();
	void showCancelButton();

protected:
	void customEvent(QEvent* event) override;
	void notifyFontChanged() override;
	void notifyVisibilityChanged(bool visible) override;

public:
	ScriptingConsole(QWidget* parent, const QString& providerName, const QString& instanceName, ScriptingInstanceRef instance);
	virtual ~ScriptingConsole();

	QString getProviderName() const { return m_providerName; }
	QString getInstanceName() const { return m_instanceName; }
	ScriptingInstanceRef getInstance() { return m_instance; }

	void clearConsole();
	void hideConsole();

	void addInput(const std::string& text);

	virtual void NotifyOutput(const std::string& text) override;
	virtual void NotifyError(const std::string& text) override;
	virtual void NotifyInputReadyStateChanged(BNScriptingProviderInputReadyState state) override;

	void moveUpInHistory();
	void moveDownInHistory();
};
