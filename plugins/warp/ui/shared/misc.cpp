#include "misc.h"

#include <QGridLayout>
#include <QHeaderView>

#include "action.h"
#include "fontsettings.h"
#include "render.h"
#include "theme.h"

void TokenDataDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    painter->save();

    auto tokenData = index.data(Qt::UserRole).value<TokenData>();

    // Draw either the selected row or background color.
    QVariant background = index.data(Qt::BackgroundRole);
    if (background.canConvert<QBrush>())
        painter->fillRect(option.rect, background.value<QBrush>());
    else if (option.state & QStyle::State_Selected)
        painter->fillRect(option.rect, option.palette.highlight());
    painter->translate(option.rect.topLeft());


    auto renderContext = RenderContext((QWidget*)option.widget);
    renderContext.init(*painter);
    HighlightTokenState highlightState;
    renderContext.drawDisassemblyLine(*painter, 5, 5, {tokenData.tokens.begin(), tokenData.tokens.end()}, highlightState);

    painter->restore();
}

QSize TokenDataDelegate::sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    auto tokenData = index.data(Qt::UserRole).value<TokenData>();
    auto renderContext = RenderContext((QWidget*)option.widget);
    QFontMetrics fontMetrics = QFontMetrics(renderContext.getFont());
    QString line = "";
    for (const auto &token: tokenData.tokens)
        line += token.text;
    int width = qMax(0, fontMetrics.horizontalAdvance(line));
    return QSize(width, renderContext.getFontHeight());
}

void AddressColorDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyleOptionViewItem opt = option;
    initStyleOption(&opt, index);

    opt.font = getMonospaceFont(qobject_cast<QWidget*>(parent()));
    opt.palette.setColor(QPalette::Text, getThemeColor(BNThemeColor::AddressColor));
    opt.displayAlignment = Qt::AlignCenter | Qt::AlignVCenter;

    QStyledItemDelegate::paint(painter, opt, index);
}

bool GenericTextFilterModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    auto filterString = filterRegularExpression().pattern();
    if (filterString.isEmpty())
        return true;

    for (int i = 0; i < sourceModel()->columnCount(); i++)
    {
        auto index = sourceModel()->index(sourceRow, i, sourceParent);
        auto data = QRegularExpression::escape(index.data().toString());
        if (data.contains(filterString, Qt::CaseInsensitive))
            return true;
    }

    return false;
}

bool GenericTextFilterModel::lessThan(const QModelIndex &sourceLeft, const QModelIndex &sourceRight) const
{
    auto leftData = sourceLeft.data().toString();
    auto rightData = sourceRight.data().toString();
    return QString::localeAwareCompare(leftData, rightData) < 0;
}
