#include <string.h>
#include <time.h>
#include "headers.h"
#include "fontsettings.h"
#include "theme.h"
#include "viewframe.h"


NavigationLabel::NavigationLabel(const QString& text, QColor color, const std::function<void()>& func):
	QLabel(text), m_func(func)
{
	QPalette style(palette());
	style.setColor(QPalette::WindowText, color);
	setPalette(style);
	setFont(getMonospaceFont(this));
}


void NavigationLabel::mousePressEvent(QMouseEvent*)
{
	m_func();
}


NavigationAddressLabel::NavigationAddressLabel(const QString& text):
	NavigationLabel(text, getThemeColor(AddressColor), [this]() { clickEvent(); })
{
	m_address = text.toULongLong(nullptr, 0);
}


void NavigationAddressLabel::clickEvent()
{
	ViewFrame* viewFrame = ViewFrame::viewFrameForWidget(this);
	if (viewFrame)
		viewFrame->navigate("Linear:" + viewFrame->getCurrentDataType(), m_address);
}


NavigationCodeLabel::NavigationCodeLabel(const QString& text):
	NavigationLabel(text, getThemeColor(CodeSymbolColor), [this]() { clickEvent(); })
{
	m_address = text.toULongLong(nullptr, 0);
}


void NavigationCodeLabel::clickEvent()
{
	ViewFrame* viewFrame = ViewFrame::viewFrameForWidget(this);
	if (viewFrame)
		viewFrame->navigate("Graph:" + viewFrame->getCurrentDataType(), m_address);
}


Headers::Headers(): m_columns(1), m_rowsPerColumn(8)
{
}


void Headers::AddField(const QString& title, const QString& value, HeaderFieldType type)
{
	m_fields.push_back(HeaderField { title, {value}, type });
}


void Headers::AddField(const QString& title, const std::vector<QString>& values, HeaderFieldType type)
{
	m_fields.push_back(HeaderField { title, values, type });
}


GenericHeaders::GenericHeaders(BinaryViewRef data)
{
	AddField("Type", QString::fromStdString(data->GetTypeName()));
	if (data->GetDefaultPlatform())
		AddField("Platform", QString::fromStdString(data->GetDefaultPlatform()->GetName()));
	if (data->IsValidOffset(data->GetEntryPoint()))
		AddField("Entry Point", QString("0x") + QString::number(data->GetEntryPoint(), 16), CodeHeaderField);
	if (data->IsValidOffset(data->GetStart()))
		AddField("Current Base", QString("0x") + QString::number(data->GetStart(), 16), AddressHeaderField);
}


PEHeaders::PEHeaders(BinaryViewRef data)
{
	uint64_t peOffset = data->GetStart() + GetValueOfStructMember(data, "DOS_Header", data->GetStart(), "e_lfanew");
	uint64_t optHeaderStart = GetAddressAfterStruct(data, "COFF_Header", peOffset);

	BinaryNinja::DataBuffer peMagic = data->ReadBuffer(optHeaderStart, 2);
	bool is64bit;
	std::string optHeaderName;
	if ((peMagic.GetLength() == 2) && (peMagic[0] == 0x0b) && (peMagic[1] == 0x01))
	{
		optHeaderName = "PE32_Optional_Header";
		AddField("Type", "PE 32-bit");
		is64bit = false;
	}
	else if ((peMagic.GetLength() == 2) && (peMagic[0] == 0x0b) && (peMagic[1] == 0x02))
	{
		optHeaderName = "PE64_Optional_Header";
		AddField("Type", "PE 64-bit");
		is64bit = true;
	}
	else
	{
		AddField("Type", QString::fromStdString(data->GetTypeName()));
		if (data->GetDefaultPlatform())
			AddField("Platform", QString::fromStdString(data->GetDefaultPlatform()->GetName()));
		if (data->IsValidOffset(data->GetEntryPoint()))
			AddField("Entry Point", QString("0x") + QString::number(data->GetEntryPoint(), 16), CodeHeaderField);
		return;
	}

	uint64_t machineValue = GetValueOfStructMember(data, "COFF_Header", peOffset, "machine");
	QString machineName = GetNameOfEnumerationMember(data, "coff_machine", machineValue);
	if (machineName.startsWith("IMAGE_FILE_MACHINE_"))
		machineName = machineName.mid((int)strlen("IMAGE_FILE_MACHINE_"));
	AddField("Machine", machineName);

	uint64_t subsysValue = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "subsystem");
	QString subsysName = GetNameOfEnumerationMember(data, "pe_subsystem", subsysValue);
	if (subsysName.startsWith("IMAGE_SUBSYSTEM_"))
		subsysName = subsysName.mid((int)strlen("IMAGE_SUBSYSTEM_"));
	AddField("Subsystem", subsysName);

	uint64_t secs = GetValueOfStructMember(data, "COFF_Header", peOffset, "timeDateStamp");
	QDateTime t = QDateTime::fromSecsSinceEpoch(secs);
	AddField("Timestamp", t.toString());

	AddField("Current Base", QString("0x") + QString::number(data->GetStart(), 16), AddressHeaderField);

	uint64_t base = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "imageBase");
	AddField("Image Base", QString("0x") + QString::number(base, 16), AddressHeaderField);

	uint64_t entryPoint = base + GetValueOfStructMember(data, optHeaderName, optHeaderStart, "addressOfEntryPoint");
	AddField("Entry Point", QString("0x") + QString::number(entryPoint, 16), CodeHeaderField);

	uint64_t sectionAlign = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "sectionAlignment");
	AddField("Section Alignment", QString("0x") + QString::number(sectionAlign, 16));

	uint64_t fileAlign = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "fileAlignment");
	AddField("File Alignment", QString("0x") + QString::number(fileAlign, 16));

	uint64_t checksum = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "checkSum");
	AddField("Checksum", QString("0x") + QString::number(checksum, 16));

	uint64_t codeBase = base + GetValueOfStructMember(data, optHeaderName, optHeaderStart, "baseOfCode");
	AddField("Base of Code", QString("0x") + QString::number(codeBase, 16), AddressHeaderField);

	if (!is64bit)
	{
		uint64_t dataBase = base + GetValueOfStructMember(data, optHeaderName, optHeaderStart, "baseOfData");
		AddField("Base of Data", QString("0x") + QString::number(dataBase, 16), AddressHeaderField);
	}

	uint64_t codeSize = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "sizeOfCode");
	AddField("Size of Code", QString("0x") + QString::number(codeSize, 16));

	uint64_t initDataSize = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "sizeOfInitializedData");
	AddField("Size of Init Data", QString("0x") + QString::number(initDataSize, 16));

	uint64_t uninitDataSize = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "sizeOfUninitializedData");
	AddField("Size of Uninit Data", QString("0x") + QString::number(uninitDataSize, 16));

	uint64_t headerSize = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "sizeOfHeaders");
	AddField("Size of Headers", QString("0x") + QString::number(headerSize, 16));

	uint64_t imageSize = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "sizeOfImage");
	AddField("Size of Image", QString("0x") + QString::number(imageSize, 16));

	uint64_t stackCommit = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "sizeOfStackCommit");
	uint64_t stackReserve = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "sizeOfStackReserve");
	AddField("Stack Size", QString("0x") + QString::number(stackCommit, 16) + QString(" / 0x") +
		QString::number(stackReserve, 16));

	uint64_t heapCommit = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "sizeOfHeapCommit");
	uint64_t heapReserve = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "sizeOfHeapReserve");
	AddField("Heap Size", QString("0x") + QString::number(heapCommit, 16) + QString(" / 0x") +
		QString::number(heapReserve, 16));

	uint64_t linkerMajor = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "majorLinkerVersion");
	uint64_t linkerMinor = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "minorLinkerVersion");
	AddField("Linker Version", QString::number(linkerMajor) + QString(".") +
		QString::number(linkerMinor).rightJustified(2, '0'));

	uint64_t imageMajor = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "majorImageVersion");
	uint64_t imageMinor = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "minorImageVersion");
	AddField("Image Version", QString::number(imageMajor) + QString(".") +
		QString::number(imageMinor).rightJustified(2, '0'));

	uint64_t osMajor = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "majorOperatingSystemVersion");
	uint64_t osMinor = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "minorOperatingSystemVersion");
	AddField("OS Version", QString::number(osMajor) + QString(".") +
		QString::number(osMinor).rightJustified(2, '0'));

	uint64_t subMajor = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "majorSubsystemVersion");
	uint64_t subMinor = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "minorSubsystemVersion");
	AddField("Subsystem Version", QString::number(subMajor) + QString(".") +
		QString::number(subMinor).rightJustified(2, '0'));

	uint64_t coffCharValue = GetValueOfStructMember(data, "COFF_Header", peOffset, "characteristics");
	TypeRef coffCharEnum = data->GetTypeByName(BinaryNinja::QualifiedName("coff_characteristics"));
	if (coffCharEnum && (coffCharEnum->GetClass() == EnumerationTypeClass))
	{
		std::vector<QString> coffCharValues;
		for (auto& member: coffCharEnum->GetEnumeration()->GetMembers())
		{
			if (coffCharValue & member.value)
			{
				if (QString::fromStdString(member.name).startsWith("IMAGE_FILE_"))
					coffCharValues.push_back(QString::fromStdString(member.name).mid((int)strlen("IMAGE_FILE_")));
				else
					coffCharValues.push_back(QString::fromStdString(member.name));
			}
		}
		if (coffCharValues.size() > 0)
			AddField("COFF Characteristics", coffCharValues);
	}

	uint64_t dllCharValue = GetValueOfStructMember(data, optHeaderName, optHeaderStart, "dllCharacteristics");
	TypeRef dllCharEnum = data->GetTypeByName(BinaryNinja::QualifiedName("pe_dll_characteristics"));
	if (dllCharEnum && (dllCharEnum->GetClass() == EnumerationTypeClass))
	{
		std::vector<QString> dllCharValues;
		for (auto& member: dllCharEnum->GetEnumeration()->GetMembers())
		{
			if (dllCharValue & member.value)
			{
				if (QString::fromStdString(member.name).startsWith("IMAGE_DLLCHARACTERISTICS_"))
					dllCharValues.push_back(QString::fromStdString(member.name).mid((int)strlen("IMAGE_DLLCHARACTERISTICS_")));
				else
					dllCharValues.push_back(QString::fromStdString(member.name));
			}
		}
		if (dllCharValues.size() > 0)
			AddField("DLL Characteristics", dllCharValues);
	}

	SetColumns(3);
	SetRowsPerColumn(9);
}


uint64_t PEHeaders::GetValueOfStructMember(BinaryViewRef data, const std::string& structName, uint64_t structStart,
	const std::string& fieldName)
{
	TypeRef type = data->GetTypeByName(structName);
	if (!type)
		return 0;
	if (type->GetClass() != StructureTypeClass)
		return 0;
	StructureRef s = type->GetStructure();
	for (auto& member: s->GetMembers())
	{
		if (member.name == fieldName)
		{
			uint64_t offset = structStart + member.offset;
			size_t width = member.type->GetWidth();
			if (width > 8)
				return 0;
			uint64_t value = 0;
			data->Read(&value, offset, width);
			return value;
		}
	}
	return 0;
}


uint64_t PEHeaders::GetAddressAfterStruct(BinaryViewRef data, const std::string& structName, uint64_t structStart)
{
	TypeRef type = data->GetTypeByName(structName);
	if (!type)
		return structStart;
	return structStart + type->GetWidth();
}


QString PEHeaders::GetNameOfEnumerationMember(BinaryViewRef data, const std::string& enumName, uint64_t value)
{
	TypeRef type = data->GetTypeByName(enumName);
	if (type && (type->GetClass() == EnumerationTypeClass))
	{
		for (auto& member: type->GetEnumeration()->GetMembers())
		{
			if (member.value == value)
				return QString::fromStdString(member.name);
		}
	}
	return QString("0x") + QString::number(value, 16);
}


HeaderWidget::HeaderWidget(QWidget* parent, const Headers& header): QWidget(parent)
{
	QGridLayout* layout = new QGridLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setVerticalSpacing(1);
	int row = 0;
	int col = 0;
	for (auto& field: header.GetFields())
	{
		layout->addWidget(new QLabel(field.title + ": "), row, col * 3);
		for (auto& value: field.values)
		{
			QWidget* label;
			if (field.type == AddressHeaderField)
			{
				label = new NavigationAddressLabel(value);
			}
			else if (field.type == CodeHeaderField)
			{
				label = new NavigationCodeLabel(value);
			}
			else
			{
				label = new QLabel(value);
				label->setFont(getMonospaceFont(this));
			}
			layout->addWidget(label, row, col * 3 + 1);
			row++;
		}
		if ((header.GetColumns() > 1) && (row >= (int)header.GetRowsPerColumn()) && ((col + 1) < (int)header.GetColumns()))
		{
			row = 0;
			col++;
		}
	}
	for (col = 1; col < (int)header.GetColumns(); col++)
		layout->setColumnMinimumWidth(col * 3 - 1, UIContext::getScaledWindowSize(20, 20).width());
	layout->setColumnStretch((int)header.GetColumns() * 3 - 1, 1);
	setLayout(layout);
}
