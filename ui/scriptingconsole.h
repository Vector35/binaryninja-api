#pragma once

#include <QtCore/QTimer>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QWidget>
#include <QtWidgets/QDialog>
#include <QtWidgets/QListView>
#include <QtCore/QAbstractListModel>
#include <QtCore/QMimeData>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
#include <functional>
#include "binaryninjaapi.h"
#include "action.h"
#include "dockhandler.h"
#include "uitypes.h"

#define SCRIPT_OUTPUT_UPDATE_INTERVAL 100
#define SCRIPT_HISTORY_LENGTH 100

class ScriptingConsole;

class BINARYNINJAUIAPI ScriptingCompletionModel: public QAbstractListModel
{
	Q_OBJECT
	std::vector<std::string> m_completions;

public:
	ScriptingCompletionModel(QWidget* parent);

	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	void setModelData(const std::vector<std::string>& completions);
};

class BINARYNINJAUIAPI ScriptingCompletionPopup: public QDialog
{
	Q_OBJECT

	QListView* m_list;
	ScriptingCompletionModel* m_model;

public:
	ScriptingCompletionPopup(QWidget* parent);
	void showWithData(QPoint pt, int cursorSize, const std::vector<std::string>& completions);
	bool handleKeyEvent(QKeyEvent* event);

private Q_SLOTS:
	void clickRow(const QModelIndex& index);

Q_SIGNALS:
	void complete(QString text);
};

class BINARYNINJAUIAPI ScriptingConsoleEdit: public QTextEdit
{
	Q_OBJECT
public:
	typedef std::function<std::vector<std::string>(const std::string&)> CompletionCallback;

private:
	ScriptingConsole* m_console;
	int m_charHeight;
	bool m_continuation;
	CompletionCallback m_completionCallback;
	ScriptingCompletionPopup* m_popup;

	uint64_t m_completionRegionStart;
	uint64_t m_completionRegionInitialStop;
	uint64_t m_completionRegionStop;

public:
	ScriptingConsoleEdit(ScriptingConsole* parent);
	void setCharHeight(int height);
	void setContinutation(bool cont);
	void setCompletionCallback(CompletionCallback callback) { m_completionCallback = callback; }
	void insertFromMimeData(const QMimeData * source) override;


private Q_SLOTS:
	void complete(QString text);

protected:
	virtual void keyPressEvent(QKeyEvent* event) override;
};

class BINARYNINJAUIAPI ScriptingConsoleOutput: public QTextEdit
{
	Q_OBJECT

	ScriptingConsole* m_console;
	UIActionHandler* m_handler;
	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	BinaryViewRef m_data;
	Menu* m_menu;

public:
	ScriptingConsoleOutput(ScriptingConsole* parent, Menu* menu);
	bool IsNavigable(const QString& str, const std::pair<int, int>& offsetLen, uint64_t& value, bool highlight) const;
protected:
	void contextMenuEvent(QContextMenuEvent* event) override;

public Q_SLOTS:
	virtual void mousePressEvent(QMouseEvent* event) override;
	void viewChanged(QWidget* frame);
};

class ScriptingConsoleWidget;

class BINARYNINJAUIAPI ScriptingConsole: public QWidget, public DockContextHandler, BinaryNinja::ScriptingOutputListener
{
	Q_OBJECT
	Q_INTERFACES(DockContextHandler)

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
	void consoleTextChanged();
	void cancel();
	void showCancelButton();

Q_SIGNALS:
	void viewChanged(QWidget* frame);

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
	virtual void notifyViewChanged(ViewFrame* frame) override;

	void moveUpInHistory();
	void moveDownInHistory();
};
