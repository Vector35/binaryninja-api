#include "fileinfo.h"
#include "fontsettings.h"
#include "theme.h"
#include <QClipboard>
#include <QApplication>
#include <QToolTip>
#include <QPainter>

class CopyableLabel : public QLabel
{
	QColor m_desiredColor {};

  public:
	CopyableLabel(const QString& text, const QColor& color) : QLabel(text), m_desiredColor(color)
	{
		this->setMouseTracking(true);
		auto style = QPalette(palette());
		style.setColor(QPalette::WindowText, m_desiredColor);
		setPalette(style);
		this->setToolTip("Copy");
	}

	void enterEvent(QEnterEvent* event) override
	{
		auto font = this->font();
		font.setBold(true);
		this->setFont(font);
		QToolTip::showText(event->globalPosition().toPoint(), this->toolTip());
	}

	void leaveEvent(QEvent* event) override
	{
		auto font = this->font();
		font.setBold(false);
		this->setFont(font);
		QToolTip::hideText();
	}

	void mousePressEvent(QMouseEvent* event) override
	{
		if (event->button() == Qt::LeftButton)
			QApplication::clipboard()->setText(this->text());
	}
};

void FileInfoWidget::addField(const QString& name, const QVariant& value)
{
	auto& [row, column] = this->m_fieldPosition;

	const auto valueLabel = new QLabel(value.toString());
	valueLabel->setFont(getMonospaceFont(this));

	this->m_layout->addWidget(new QLabel(name), row, column);
	this->m_layout->addWidget(valueLabel, row++, column + 1);
}

void FileInfoWidget::addHashField(
    const QString& hashName, const QCryptographicHash::Algorithm& algorithm, const QByteArray& data)
{
	auto& [row, column] = this->m_fieldPosition;

	const auto hashFieldColor = getThemeColor(AlphanumericHighlightColor);
	const auto crypto = QCryptographicHash::hash(data, algorithm);
	const auto hashLabel = new CopyableLabel(crypto.toHex(), hashFieldColor);
	hashLabel->setFont(getMonospaceFont(this));

	this->m_layout->addWidget(new QLabel(hashName), row, column);
	this->m_layout->addWidget(hashLabel, row++, column + 1);
}

FileInfoWidget::FileInfoWidget(QWidget* parent, BinaryViewRef bv)
{
	this->m_layout = new QGridLayout();
	this->m_layout->setContentsMargins(0, 0, 0, 0);
	this->m_layout->setVerticalSpacing(1);

	const auto view = bv->GetParentView() ? bv->GetParentView() : bv;
	const auto filePath = bv->GetFile()->GetOriginalFilename();
	this->addField("Path: ", filePath.c_str());

	const auto fileSize = QString::number(view->GetLength(), 16).prepend("0x");
	this->addField("Size: ", fileSize);

	const auto bufferSize = fileSize.toUInt(nullptr, 16);
	const auto fileBuffer = std::make_unique<char[]>(bufferSize);
	view->Read(fileBuffer.get(), 0, bufferSize);

	const auto fileBytes = QByteArray(fileBuffer.get(), bufferSize);
	this->addHashField("MD5: ", QCryptographicHash::Md5, fileBytes);
	this->addHashField("SHA-1: ", QCryptographicHash::Sha1, fileBytes);
	this->addHashField("SHA-256: ", QCryptographicHash::Sha256, fileBytes);

	const auto scaledWidth = UIContext::getScaledWindowSize(20, 20).width();
	this->m_layout->setColumnMinimumWidth(FileInfoWidget::m_maxColumns * 3 - 1, scaledWidth);
	this->m_layout->setColumnStretch(FileInfoWidget::m_maxColumns * 3 - 1, 1);
	setLayout(this->m_layout);
}