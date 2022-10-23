#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include "binaryninjaapi.h"
#include "uicontext.h"

/*!

	\defgroup platformdialog PlatformDialog
 	\ingroup uiapi
*/

/*!

    \ingroup platformdialog
*/
class BINARYNINJAUIAPI PlatformDialog : public QDialog
{
	Q_OBJECT

	QComboBox* m_arch;
	QComboBox* m_os;
	QComboBox* m_platform;

	std::map<QString, PlatformRef> m_platformsByName;
	PlatformRef m_selectedPlatform;

  public:
	PlatformDialog(QWidget* parent, ArchitectureRef defaultArch = nullptr);

	PlatformRef getPlatform();
	void saveDefaults();

  private Q_SLOTS:
	void architectureChanged(const QString& name);
	void osChanged(const QString& name);

	void selectPlatform();
};
