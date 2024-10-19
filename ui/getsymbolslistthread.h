#pragma once

#ifndef BINARYNINJAUI_BINDINGS
	#include <QtCore/QThread>
#endif
#include "binaryninjaapi.h"
#include "uitypes.h"


#ifdef BINARYNINJAUI_BINDINGS
// QThread has issues working in the bindings on some platforms
class GetSymbolsListThread;
#else

/*!

    \ingroup uiapi
*/
class BINARYNINJAUIAPI GetSymbolsListThread : public QThread
{
	Q_OBJECT

	BinaryViewRef m_view;
	QStringList m_symbolsList;
	QStringList m_additionalListEntries;

protected:
	virtual void run() override;

public:
	GetSymbolsListThread(BinaryViewRef view, QStringList additionalListEntries);
	void cancel();

signals:
	void symbolsListReady(const QStringList& symbolsList);
};
#endif
