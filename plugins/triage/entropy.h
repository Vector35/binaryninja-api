#pragma once

#include <QtWidgets/QWidget>
#include <QtGui/QImage>
#include <thread>
#include <mutex>
#include "uitypes.h"


class EntropyThread
{
	BinaryViewRef m_data;
	QImage* m_image;
	size_t m_blockSize;
	bool m_updated, m_running;
	std::thread m_thread;
	double m_averageEntropy;
	int m_sampleCount;
	mutable std::mutex m_mutex;

  public:
	EntropyThread(BinaryViewRef data, size_t blockSize, QImage* image);
	~EntropyThread();

	void Run();
	bool IsUpdated() { return m_updated; }
	void ResetUpdated() { m_updated = false; }
	double GetAverageEntropy() const;
};


class TriageView;

class EntropyWidget : public QWidget
{
	Q_OBJECT

	TriageView* m_view;
	BinaryViewRef m_data, m_rawData;
	size_t m_blockSize;
	int m_width;
	QImage m_image;
	EntropyThread* m_thread;

  public:
	EntropyWidget(QWidget* parent, TriageView* view, BinaryViewRef data);
	virtual ~EntropyWidget();

	virtual QSize sizeHint() const override;
	double getAverageEntropy() const;

  Q_SIGNALS:
	void entropyUpdated(double avgEntropy);

  protected:
	virtual void paintEvent(QPaintEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;

  private Q_SLOTS:
	void timerExpired();
};
