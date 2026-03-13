#pragma once
#include <QCheckBox>
#include <QDialog>
#include <qmetatype.h>
#include <QSortFilterProxyModel>
#include <qstandarditemmodel.h>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QVector>
#include <utility>

#include "binaryninjaapi.h"
#include "filter.h"
#include "warp.h"

// Used to serialize into the item data for rendering with TokenDataDelegate.
struct TokenData
{
	QVector<BinaryNinja::InstructionTextToken> tokens {};

	TokenData() = default;

	TokenData(const std::string& name);

	TokenData(const BinaryNinja::Type& type, const std::string& name);

	TokenData(const std::vector<BinaryNinja::InstructionTextToken>& tokens)
	{
		for (const auto& token : tokens)
			this->tokens.push_back(token);
	}

	TokenData(const BinaryNinja::InstructionTextToken& token) { this->tokens.push_back(token); }

	QString toString() const
	{
		QStringList tokenStrings;
		for (const auto& token : tokens)
		{
			tokenStrings.append(QString::fromStdString(token.text));
		}
		return tokenStrings.join("");
	}
};

Q_DECLARE_METATYPE(TokenData)

class TokenDataDelegate final : public QStyledItemDelegate
{
	Q_OBJECT

public:
	explicit TokenDataDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}

	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;

	QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};

class AddressColorDelegate final : public QStyledItemDelegate
{
	Q_OBJECT

public:
	explicit AddressColorDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}

	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};

class SourcePathDelegate : public QStyledItemDelegate
{
	Q_OBJECT

public:
	explicit SourcePathDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}
	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};

class GenericTextFilterModel : public QSortFilterProxyModel
{
	Q_OBJECT

public:
	GenericTextFilterModel(QObject* parent) : QSortFilterProxyModel(parent) {}

	~GenericTextFilterModel() override = default;

	bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;

	bool lessThan(const QModelIndex& sourceLeft, const QModelIndex& sourceRight) const override;
};

// Used to parse qualifiers out of a user-supplied string (or "query")
struct ParsedQuery
{
	// The actual query, without the qualifiers like source:<uuid>
	QString query;
	// The qualifiers used to build other optional parts of the query.
	QHash<QString, QString> qualifiers;

	ParsedQuery(QString query, const QHash<QString, QString>& qualifiers) :
		query(std::move(query)), qualifiers(qualifiers)
	{}

	explicit ParsedQuery(const QString& rawQuery);

	[[nodiscard]] std::optional<QString> GetValue(const QString& key) const
	{
		const auto it = qualifiers.constFind(key);
		if (it == qualifiers.constEnd() || it->isEmpty())
			return std::nullopt;
		return it.value();
	}
};

// TODO: Consolidate with `WARP\\Remove Matched Function` plugin command?
class WarpRemoveMatchDialog : public QDialog
{
	Q_OBJECT

public:
	explicit WarpRemoveMatchDialog(QWidget* parent, FunctionRef func);

	bool execute();

private:
	FunctionRef m_func;
	QCheckBox* m_ignoreCheck {nullptr};
};

constexpr const char* ALLOWED_TAGS_SETTING = "warp.fetcher.allowedSourceTags";
constexpr const char* BATCH_SIZE_SETTING = "warp.fetcher.fetchBatchSize";

inline std::vector<Warp::SourceTag> GetAllowedTagsFromView(const BinaryViewRef& view)
{
	auto settings = BinaryNinja::Settings::Instance();
	if (!settings->Contains(ALLOWED_TAGS_SETTING))
		return {};
	return settings->Get<std::vector<std::string>>(ALLOWED_TAGS_SETTING, view);
}

inline void SetTagsToView(const BinaryViewRef& view, const std::vector<Warp::SourceTag>& tags)
{
	auto settings = BinaryNinja::Settings::Instance();
	if (!settings->Contains(ALLOWED_TAGS_SETTING))
		return;
	settings->Set(ALLOWED_TAGS_SETTING, tags, view);
}

inline size_t GetBatchSizeFromView(const BinaryViewRef& view)
{
	auto settings = BinaryNinja::Settings::Instance();
	if (!settings->Contains(BATCH_SIZE_SETTING))
		return 10000;
	return settings->Get<uint64_t>(BATCH_SIZE_SETTING, view);
}

inline void RegisterPluginAction(
	std::string name, std::function<void(const UIActionContext&)> action,
	std::function<bool(const UIActionContext&)> isValid = [](const UIActionContext&) { return true; })
{
	const QString actionName = QString("WARP\\%1").arg(QString::fromStdString(name));
	if (!UIAction::isActionRegistered(actionName))
		UIAction::registerAction(actionName);
	UIActionHandler::globalActions()->bindAction(actionName, UIAction(action, isValid));
	Menu::mainMenu("Plugins")->addAction(actionName, "Plugins");
}