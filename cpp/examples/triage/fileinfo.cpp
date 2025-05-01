#include "fileinfo.h"
#include "fontsettings.h"
#include "theme.h"
#include "copyablelabel.h"
#include <QClipboard>
#include <QApplication>
#include <QToolTip>
#include <QPainter>
#include <QtConcurrent/QtConcurrent>
#include <QFuture>
#include <QFutureWatcher>

void FileInfoWidget::addCopyableField(const QString& name, const QVariant& value)
{
	auto& [row, column] = this->m_fieldPosition;

	const auto valueLabel = new CopyableLabel(value.toString(), getThemeColor(AlphanumericHighlightColor));
	valueLabel->setFont(getMonospaceFont(this));

	this->m_layout->addWidget(new QLabel(name), row, column);
	this->m_layout->addWidget(valueLabel, row++, column + 1);
}

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
	auto hashLabel = new CopyableLabel("Calculating...", hashFieldColor);
	hashLabel->setFont(getMonospaceFont(this));

	this->m_layout->addWidget(new QLabel(hashName), row, column);
	this->m_layout->addWidget(hashLabel, row++, column + 1);

	// Process the hash calculations in a separate thread and update the label when done
	QPointer<QFutureWatcher<QByteArray>> watcher = new QFutureWatcher<QByteArray>(this);
	connect(watcher, &QFutureWatcher<QByteArray>::finished, this, [watcher, hashLabel]() {
		if (watcher)
		{
			hashLabel->setText(watcher->result().toHex());
			watcher->deleteLater();
		}
	});
	QFuture<QByteArray> future = QtConcurrent::run([data, algorithm]() {
		return QCryptographicHash::hash(data, algorithm);
	});
	watcher->setFuture(future);
	connect(this, &QObject::destroyed, this, [watcher]() {
		if (watcher && watcher->isRunning()) {
			watcher->cancel();
			watcher->waitForFinished();
		}
	});
}

FileInfoWidget::FileInfoWidget(QWidget* parent, BinaryViewRef bv)
{
	this->m_layout = new QGridLayout();
	this->m_layout->setContentsMargins(0, 0, 0, 0);
	this->m_layout->setVerticalSpacing(1);

	const auto view = bv->GetParentView() ? bv->GetParentView() : bv;
	const auto filePath = bv->GetFile()->GetOriginalFilename();
	this->addCopyableField("Path: ", filePath.c_str());

	const auto fileSize = QString::number(view->GetLength(), 16).prepend("0x");
	this->addCopyableField("Size: ", fileSize);

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