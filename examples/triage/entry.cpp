#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <algorithm>
#include <vector>
#include "entry.h"
#include "headers.h"
#include "fontsettings.h"


EntryWidget::EntryWidget(QWidget* parent, BinaryViewRef data) : QWidget(parent)
{
	QGridLayout* layout = new QGridLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setVerticalSpacing(1);
	layout->setHorizontalSpacing(UIContext::getScaledWindowSize(16, 16).width());

	size_t maxNameLen = 0;
	for (auto& func : data->GetAllEntryFunctions())
	
		if (func->GetSymbol()->GetFullName().size() > maxNameLen)
			maxNameLen = func->GetSymbol()->GetFullName().size();
	if (maxNameLen > 32)
		maxNameLen = 32;

	for (auto& func : data->GetAllEntryFunctions())
        m_entry.push_back(func);

	sort(m_entry.begin(), m_entry.end(),
	    [&](FunctionRef a, FunctionRef b) { return a->GetStart() < b->GetStart(); });

	int row = 0;
	for (auto& func : m_entry)
	{
		std::string name = func->GetSymbol()->GetFullName();
		if (name.size() > maxNameLen)
			name = name.substr(0, maxNameLen - 1) + std::string("…");
		QLabel* nameLabel = new QLabel(QString::fromStdString(name));
		nameLabel->setFont(getMonospaceFont(this));
		layout->addWidget(nameLabel, row, 0);

		QString begin = QString("0x") + QString::number(func->GetStart(), 16);
		QHBoxLayout* beginLayout = new QHBoxLayout();
		NavigationAddressLabel* beginLabel = new NavigationAddressLabel(begin);
		beginLayout->addWidget(beginLabel);
		layout->addLayout(beginLayout, row, 1);

		row++;
	}

	layout->setColumnStretch(5, 1);
	setLayout(layout);
}
