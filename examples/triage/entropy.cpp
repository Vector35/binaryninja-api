#include <QtCore/QTimer>
#include <QtGui/QPainter>
#include "entropy.h"
#include "view.h"
#include "theme.h"


EntropyThread::EntropyThread(BinaryViewRef data, int width, size_t blockSize)
{
	m_data = data;
	m_image = QImage(width, 1, QImage::Format_ARGB32);
	m_blockSize = blockSize;
	m_updated = false;
	m_running = true;
	m_thread = std::thread([=]() { Run(); });
}


EntropyThread::~EntropyThread()
{
	m_running = false;
	m_thread.join();
}


void EntropyThread::Run()
{
	int width = m_image.width();
	for (int i = 0; i < width; i++)
	{
		if (!m_running)
			break;
		std::vector<float> entropy = m_data->GetEntropy(m_data->GetStart() + ((uint64_t)i * m_blockSize), m_blockSize, m_blockSize);
		int v;
		if (entropy.size() == 0)
			v = 0;
		else
			v = (int)(entropy[0] * 255);
		if (v >= 240)
		{
			QColor color = getThemeColor(YellowStandardHighlightColor);
			m_image.setPixelColor(i, 0, color);
		}
		else
		{
			QColor baseColor = getThemeColor(FeatureMapBaseColor);
			QColor entropyColor = getThemeColor(BlueStandardHighlightColor);
			QColor color = mixColor(baseColor, entropyColor, (uint8_t)v);
			m_image.setPixelColor(i, 0, color);
		}
		m_updated = true;
	}
}


EntropyWidget::EntropyWidget(QWidget* parent, TriageView* view, BinaryViewRef data): QWidget(parent)
{
	m_view = view;
	m_data = data;
	m_rawData = data->GetFile()->GetViewOfType("Raw");

	m_blockSize = 1024;
	m_width = (int)(m_rawData->GetLength() / (uint64_t)m_blockSize);
	m_thread = new EntropyThread(m_rawData, m_width, m_blockSize);

	QTimer* timer = new QTimer();
	connect(timer, &QTimer::timeout, this, &EntropyWidget::timerExpired);
	timer->setInterval(100);
	timer->setSingleShot(false);
	timer->start();

	setMinimumHeight(UIContext::getScaledWindowSize(32, 32).height());
}


EntropyWidget::~EntropyWidget()
{
	delete m_thread;
}


void EntropyWidget::paintEvent(QPaintEvent*)
{
	QPainter p(this);
	p.drawImage(rect(), m_thread->GetImage());
	p.drawRect(rect());
}


QSize EntropyWidget::sizeHint() const
{
	return QSize(640, 32);
}


void EntropyWidget::timerExpired()
{
	if (m_thread->IsUpdated())
	{
		m_thread->ResetUpdated();
		update();
	}
}


void EntropyWidget::mousePressEvent(QMouseEvent* event)
{
	if (event->button() != Qt::LeftButton)
		return;
	float frac = (float)event->x() / (float)rect().width();
	uint64_t offset = (uint64_t)(frac * m_width * m_blockSize);
	m_view->navigateToFileOffset(offset);
}
