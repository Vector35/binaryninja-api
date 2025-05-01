#include "librariesinfo.h"
#include "theme.h"


LibrariesWidget::LibrariesWidget(QWidget* parent, BinaryViewRef bv)
{
	auto layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);

	auto libMetadata = bv->QueryMetadata("Libraries");
	auto libFoundMetadata = bv->QueryMetadata("LibraryFound");
	if (libMetadata && libFoundMetadata && libMetadata->IsStringList() && libFoundMetadata->IsStringList() && libMetadata->Size() == libFoundMetadata->Size())
	{
		const auto libNames = libMetadata->GetStringList();
		const auto typeLibPaths = libFoundMetadata->GetStringList();
		for (size_t i = 0; i < libNames.size(); ++i)
		{
			auto lib = libNames[i];
			auto typeLib = typeLibPaths[i];
			auto libWidget = new QLabel(QString::fromStdString("  " + lib));
			QString toolTip;
			auto style = QPalette(palette());
			if (typeLib.empty())
			{
				toolTip = "Type library: not found";
				style.setColor(QPalette::WindowText, getThemeColor(NotPresentColor));
			}
			else
			{
				toolTip = QString::fromStdString("Type library: " + typeLib);
			}
			libWidget->setToolTip(toolTip);
			libWidget->setPalette(style);
			layout->addWidget(libWidget);
		}
	}
	else if (libMetadata && libMetadata->IsStringList())
	{
		for (const auto& lib : libMetadata->GetStringList())
			layout->addWidget(new QLabel(QString::fromStdString(lib)));
	}
	else
	{
		auto style = QPalette(palette());
		style.setColor(QPalette::WindowText, getThemeColor(NotPresentColor));
		auto noLibWidget = new QLabel("No libraries found");
		noLibWidget->setPalette(style);
		layout->addWidget(noLibWidget);
	}
	setLayout(layout);
}
