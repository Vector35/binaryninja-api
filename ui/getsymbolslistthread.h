#pragma once

#ifndef BINARYNINJAUI_BINDINGS
	#include <QtCore/QThread>
	#include <QtCore/QEvent>
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

	QStringList m_allSymbols;
	std::function<void()> m_completeFunc;
	std::mutex m_mutex;
	bool m_done;
	BinaryViewRef m_view;

  protected:
	virtual void run() override;

  public:
	GetSymbolsListThread(BinaryViewRef view, const std::function<void()>& completeFunc);
	void cancel();

	static int m_eventType;
	int GetEventType() { return GetSymbolsListThread::m_eventType; }

	const QStringList& getSymbols() const { return m_allSymbols; }
};
#endif
