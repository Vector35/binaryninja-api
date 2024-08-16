#pragma once

#include <QtWidgets/QLabel>
#include <QtWidgets/QWidget>
#include <functional>
#include "uitypes.h"


class NavigationLabel : public QLabel
{
	std::function<void()> m_func;

  public:
	NavigationLabel(const QString& text, QColor color, const std::function<void()>& func);

  protected:
	virtual void mousePressEvent(QMouseEvent* event) override;
};


class NavigationAddressLabel : public NavigationLabel
{
	void clickEvent();

  public:
	NavigationAddressLabel(const QString& text);
};


class NavigationCodeLabel : public NavigationLabel
{
	void clickEvent();

  public:
	NavigationCodeLabel(const QString& text);
};


enum HeaderFieldType
{
	TextHeaderField,
	AddressHeaderField,
	CodeHeaderField
};


struct HeaderField
{
	QString title;
	std::vector<QString> values;
	HeaderFieldType type;
};


class Headers
{
	std::vector<HeaderField> m_fields;
	size_t m_columns, m_rowsPerColumn;

  public:
	Headers();
	void AddField(const QString& title, const QString& value, HeaderFieldType type = TextHeaderField);
	void AddField(const QString& title, const std::vector<QString>& values, HeaderFieldType type = TextHeaderField);
	const std::vector<HeaderField>& GetFields() const { return m_fields; }
	void SetColumns(size_t cols) { m_columns = cols; }
	void SetRowsPerColumn(size_t rows) { m_rowsPerColumn = rows; }
	size_t GetColumns() const { return m_columns; }
	size_t GetRowsPerColumn() const { return m_rowsPerColumn; }
};


class GenericHeaders : public Headers
{
  public:
	GenericHeaders(BinaryViewRef data);
};


class PEHeaders : public Headers
{
	uint64_t GetValueOfStructMember(
	    BinaryViewRef data, const std::string& structName, uint64_t structStart, const std::string& fieldName);
	uint64_t GetAddressAfterStruct(BinaryViewRef data, const std::string& structName, uint64_t structStart);
	QString GetNameOfEnumerationMember(BinaryViewRef data, const std::string& enumName, uint64_t value);

  public:
	PEHeaders(BinaryViewRef data);
};


class HeaderWidget : public QWidget
{
  public:
	HeaderWidget(QWidget* parent, const Headers& headers);
};
