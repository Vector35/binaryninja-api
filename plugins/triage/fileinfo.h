#pragma once
#include <QtWidgets/QLabel>
#include <QtWidgets/QWidget>
#include <QCryptographicHash>
#include "uitypes.h"
#include "viewframe.h"

class EntropyWidget;

class FileInfoWidget : public QWidget
{
	Q_OBJECT

	static constexpr std::int32_t m_maxColumns {2};
	std::pair<std::int32_t, std::int32_t> m_fieldPosition {};  // row, column
	QGridLayout* m_layout {};
	QLabel* m_entropyLabel {};

	void addField(const QString& name, const QVariant& value);
	void addCopyableField(const QString& name, const QVariant& value);
	void addCopyableFieldWithElide(const QString& name, const QVariant& value, int maxWidth);
	void addHashFields(BinaryViewRef view);

  public:
	FileInfoWidget(QWidget* parent, BinaryViewRef bv, EntropyWidget* entropyWidget);

  private Q_SLOTS:
	void updateEntropy(double avgEntropy);
};
