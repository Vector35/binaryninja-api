#include "misc.h"

#include <QDialogButtonBox>
#include <QGridLayout>
#include <QHeaderView>

#include "action.h"
#include "fontsettings.h"
#include "render.h"
#include "theme.h"

TokenData::TokenData(const std::string& name)
{
	tokens.emplace_back(255, TextToken, name);
}

TokenData::TokenData(const BinaryNinja::Type& type, const std::string& name)
{
	for (const auto& token : type.GetTokensBeforeName())
		tokens.emplace_back(token);
	tokens.emplace_back(255, TextToken, " ");
	tokens.emplace_back(255, TextToken, name);
	for (const auto& token : type.GetTokensAfterName())
		tokens.emplace_back(token);
}

void TokenDataDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
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


	auto renderContext = RenderContext(const_cast<QWidget*>(option.widget));
	renderContext.init(*painter);
	HighlightTokenState highlightState;
	renderContext.drawDisassemblyLine(
		*painter, 5, 5, {tokenData.tokens.begin(), tokenData.tokens.end()}, highlightState);

	painter->restore();
}

QSize TokenDataDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const
{
	auto tokenData = index.data(Qt::UserRole).value<TokenData>();
	auto renderContext = RenderContext(const_cast<QWidget*>(option.widget));
	QFontMetrics fontMetrics = QFontMetrics(renderContext.getFont());
	QString line = "";
	for (const auto& token : tokenData.tokens)
		line += token.text;
	int width = qMax(0, fontMetrics.horizontalAdvance(line));
	return QSize(width, renderContext.getFontHeight());
}

void AddressColorDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
{
	QStyleOptionViewItem opt = option;
	initStyleOption(&opt, index);

	opt.font = getMonospaceFont(qobject_cast<QWidget*>(parent()));
	opt.palette.setColor(QPalette::Text, getThemeColor(BNThemeColor::AddressColor));
	opt.displayAlignment = Qt::AlignCenter | Qt::AlignVCenter;

	QStyledItemDelegate::paint(painter, opt, index);
}

void SourcePathDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
{
	QStyleOptionViewItem opt = option;
	initStyleOption(&opt, index);

	// Draw background and selection highlights
	opt.widget->style()->drawControl(QStyle::CE_ItemViewItem, &opt, painter, opt.widget);

	QString text = index.data(Qt::DisplayRole).toString();
	int sepIdx = qMax(text.lastIndexOf('/'), text.lastIndexOf('\\'));
	QString dirPart = sepIdx != -1 ? text.left(sepIdx + 1) : "";
	QString filePart = sepIdx != -1 ? text.mid(sepIdx + 1) : text;

	QFont regularFont = opt.font;
	QFont boldFont = regularFont;
	boldFont.setBold(true);

	QFontMetrics fmReg(regularFont);
	QFontMetrics fmBold(boldFont);

	// Basic padding inside the list item
	QRect textRect = opt.rect.adjusted(3, 0, -3, 0);

	int fileWidth = fmBold.horizontalAdvance(filePart);
	int dirWidth = fmReg.horizontalAdvance(dirPart);

	QString textToDrawDir;
	QString textToDrawFile = filePart;

	if (dirWidth + fileWidth > textRect.width())
	{
		if (fileWidth > textRect.width())
		{
			// The file name itself is too long, elide it
			textToDrawDir = "";
			textToDrawFile = fmBold.elidedText(filePart, Qt::ElideLeft, textRect.width());
		}
		else
		{
			// Elide the directory part so the bold file name fits
			textToDrawDir = fmReg.elidedText(dirPart, Qt::ElideLeft, textRect.width() - fileWidth);
		}
	}
	else
	{
		textToDrawDir = dirPart;
	}

	painter->save();

	// Set the proper text color based on selection state
	if (opt.state & QStyle::State_Selected)
		painter->setPen(opt.palette.highlightedText().color());
	else
		painter->setPen(opt.palette.text().color());

	// Draw the directory part
	painter->setFont(regularFont);
	painter->drawText(textRect, Qt::AlignLeft | Qt::AlignVCenter, textToDrawDir);

	// Draw the file part
	painter->setFont(boldFont);
	int dirAdvance = fmReg.horizontalAdvance(textToDrawDir);
	QRect fileRect = textRect.adjusted(dirAdvance, 0, 0, 0);
	painter->drawText(fileRect, Qt::AlignLeft | Qt::AlignVCenter, textToDrawFile);

	painter->restore();
}

bool GenericTextFilterModel::filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const
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

bool GenericTextFilterModel::lessThan(const QModelIndex& sourceLeft, const QModelIndex& sourceRight) const
{
	auto leftData = sourceLeft.data().toString();
	auto rightData = sourceRight.data().toString();
	return QString::localeAwareCompare(leftData, rightData) < 0;
}

ParsedQuery::ParsedQuery(const QString& rawQuery)
{
	query = rawQuery;
	qualifiers = {};

	// Regex capturing: key, and value (bare, quoted and unquoted)
	static QRegularExpression re(R"((^|\s)([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(?:\"([^\"]*)\"|'([^']*)'|(\S+)))",
		QRegularExpression::CaseInsensitiveOption);

	// Collect matches to remove later (from end to start to keep indices stable)
	struct Span
	{
		qsizetype start;
		qsizetype length;
		QString key;
		QString value;
	};
	QVector<Span> spans;

	auto it = re.globalMatch(rawQuery);
	while (it.hasNext())
	{
		const auto m = it.next();
		const QString key = m.captured(2).toLower();
		// Value can be in group 3 (double quotes), 4 (single quotes), or 5 (bare)
		QString val = m.captured(3);
		if (val.isNull() || val.isEmpty())
			val = m.captured(4);
		if (val.isNull() || val.isEmpty())
			val = m.captured(5);
		spans.push_back(Span {m.capturedStart(0), m.capturedLength(0), key, val});
	}

	// Keep only the last value per key (last occurrence wins, do not accumulate)
	for (const auto& s : spans)
		qualifiers[s.key] = s.value;

	// Remove matched spans from the text (replace with a single space to preserve boundaries)
	std::sort(spans.begin(), spans.end(), [](const Span& a, const Span& b) { return a.start > b.start; });
	for (const auto& s : spans)
		query.replace(s.start, s.length, QStringLiteral(" "));

	// Normalize whitespace
	query = query.simplified();
}

WarpRemoveMatchDialog::WarpRemoveMatchDialog(QWidget* parent, FunctionRef func) : QDialog(parent), m_func(func)
{
	setWindowTitle("Remove Matching Function");
	setModal(true);

	auto* vbox = new QVBoxLayout(this);
	auto* text = new QLabel(
		"Remove the match for this function? You can also mark it as ignored to prevent future automatic matches.");
	text->setWordWrap(true);
	vbox->addWidget(text);

	m_ignoreCheck = new QCheckBox("Tag function as ignored");
	m_ignoreCheck->setChecked(true);
	vbox->addWidget(m_ignoreCheck);

	auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
	connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	vbox->addWidget(buttons);
}

bool WarpRemoveMatchDialog::execute()
{
	if (!m_func)
		return false;
	if (exec() != QDialog::Accepted)
		return false;
	Warp::Function::RemoveMatch(*m_func);
	if (m_ignoreCheck->isChecked())
	{
		// TODO: For now we just assume the tag type to exist (the matcher activity will create it)
		const TagTypeRef tagType = m_func->GetView()->GetTagTypeByName("WARP: Ignored Function");
		if (!tagType)
			return false;
		const TagRef tag = new BinaryNinja::Tag(tagType, "");
		if (tagType)
			m_func->AddUserFunctionTag(tag);
	}
	m_func->Reanalyze();
	return true;
}
