#pragma once
#include <QtWidgets/QLabel>
#include <QtWidgets/QWidget>
#include <QCryptographicHash>
#include "uitypes.h"
#include "viewframe.h"

class FileInfoWidget : public QWidget
{
	static constexpr std::int32_t m_maxColumns {2};
	std::pair<std::int32_t, std::int32_t> m_fieldPosition {};  // row, column
	QGridLayout* m_layout {};

	void addField(const QString& name, const QVariant& value);
	void addHashField(const QString& hashName, const QCryptographicHash::Algorithm& algorithm, const QByteArray& data);

  public:
	FileInfoWidget(QWidget* parent, BinaryViewRef bv);
};
