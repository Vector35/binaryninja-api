#pragma once
#include <qmetatype.h>
#include <QSortFilterProxyModel>
#include <qstandarditemmodel.h>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QVector>

#include "binaryninjaapi.h"
#include "filter.h"

// Used to serialize into the item data for rendering with TokenDataDelegate.
struct TokenData
{
    QVector<BinaryNinja::InstructionTextToken> tokens {};

    TokenData() = default;

    TokenData(const std::vector<BinaryNinja::InstructionTextToken> &tokens)
    {
        for (const auto &token: tokens)
            this->tokens.push_back(token);
    }

    TokenData(const BinaryNinja::InstructionTextToken &token)
    {
        this->tokens.push_back(token);
    }

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
    explicit TokenDataDelegate(QObject *parent = nullptr) : QStyledItemDelegate(parent)
    {
    }

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;
};

class AddressColorDelegate final : public QStyledItemDelegate
{
    Q_OBJECT

public:
    explicit AddressColorDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent)
    {
    }

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};


class GenericTextFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    GenericTextFilterModel(QObject *parent): QSortFilterProxyModel(parent)
    {
    }

    ~GenericTextFilterModel() override = default;

    bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
    bool lessThan(const QModelIndex& sourceLeft, const QModelIndex& sourceRight) const override;
};
