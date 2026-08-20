#include <QtCore/QTimer>
#include <QtGui/QPainter>
#include "entropy.h"
#include "view.h"
#include "theme.h"


EntropyThread::EntropyThread(BinaryViewRef data, size_t blockSize, QImage* image)
{
	m_data = data;
	m_image = image;
	m_blockSize = blockSize;
	m_updated = false;
	m_running = true;
	m_averageEntropy = 0.0;
	m_sampleCount = 0;
	m_thread = std::thread([=, this]() { Run(); });
}


EntropyThread::~EntropyThread()
{
	m_running = false;
	m_thread.join();
}


void EntropyThread::Run()
{
	int width = m_image->width();
	for (int i = 0; i < width; i++)
	{
		if (!m_running)
			break;
		std::vector<float> entropy =
		    m_data->GetEntropy(m_data->GetStart() + ((uint64_t)i * m_blockSize), m_blockSize, m_blockSize);
		int v;
		float entropyValue = 0.0f;
		if (entropy.size() == 0)
			v = 0;
		else
		{
			entropyValue = entropy[0];
			v = (int)(entropyValue * 255);
		}

		// Update running average
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_sampleCount++;
			m_averageEntropy += (entropyValue - m_averageEntropy) / m_sampleCount;
		}

		if (v >= 240)
		{
			QColor color = getThemeColor(YellowStandardHighlightColor);
			m_image->setPixelColor(i, 0, color);
		}
		else
		{
			QColor baseColor = getThemeColor(FeatureMapBaseColor);
			QColor entropyColor = getThemeColor(BlueStandardHighlightColor);
			QColor color = mixColor(baseColor, entropyColor, (uint8_t)v);
			m_image->setPixelColor(i, 0, color);
		}
		m_updated = true;
	}
}


double EntropyThread::GetAverageEntropy() const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_averageEntropy;
}


EntropyWidget::EntropyWidget(QWidget* parent, TriageView* view, BinaryViewRef data) : QWidget(parent)
{
	m_view = view;
	m_data = data;
	m_rawData = data->GetFile()->GetViewOfType("Raw");

	m_blockSize = (size_t)((m_rawData->GetLength() / 4096) + 1);
	if (m_blockSize < 1024)
		m_blockSize = 1024;
	m_width = (int)(m_rawData->GetLength() / (uint64_t)m_blockSize);
	m_image = QImage(m_width, 1, QImage::Format_ARGB32);
	m_image.fill(QColor(0, 0, 0, 0));
	m_thread = new EntropyThread(m_rawData, m_blockSize, &m_image);

	QTimer* timer = new QTimer();
	connect(timer, &QTimer::timeout, this, &EntropyWidget::timerExpired);
	timer->setInterval(100);
	timer->setSingleShot(false);
	timer->start();

	setCursor(Qt::PointingHandCursor);
	setMouseTracking(true);
	setMinimumHeight(UIContext::getScaledWindowSize(32, 32).height());
}


EntropyWidget::~EntropyWidget()
{
	delete m_thread;
}


void EntropyWidget::paintEvent(QPaintEvent*)
{
	QPainter p(this);
	p.drawImage(rect(), m_image);
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
		emit entropyUpdated(m_thread->GetAverageEntropy());
	}
}


void EntropyWidget::mousePressEvent(QMouseEvent* event)
{
	if (event->button() != Qt::LeftButton)
		return;
	float frac = (float)event->pos().x() / (float)rect().width();
	uint64_t offset = (uint64_t)(frac * m_width * m_blockSize);
	m_view->navigateToFileOffset(offset);
}


void EntropyWidget::mouseMoveEvent(QMouseEvent* event)
{
	float frac = (float)event->pos().x() / (float)rect().width();
	uint64_t offset = (uint64_t)(frac * m_width * m_blockSize);
	uint64_t addr = 0;
	bool hasAddr = m_data->GetAddressForDataOffset(offset, addr);
	if (hasAddr)
		setToolTip(QString("0x%1").arg(addr, 0, 16));
	else
		setToolTip(QString("File offset: 0x%1").arg(offset, 0, 16));
}


double EntropyWidget::getAverageEntropy() const
{
	return m_thread->GetAverageEntropy();
}
