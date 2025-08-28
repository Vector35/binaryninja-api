//
// Created by Alexander Khosrowshahi on 8/22/25.
//

#pragma once

#include <QtWidgets/QTableView>
#include <QtWidgets/QHeaderView>
#include <QtCore/QTimer>
#include <QMenu>

/// Base class for table views in Binary Ninja views
/// - Moveable, resizeable columns with saved state
/// - QSettings save to Tables/<viewName>/<Suffix>
/// - Reset columns context menu action
class TableViewBase: public QTableView {
	Q_OBJECT

public:
	explicit TableViewBase(QWidget* parent = nullptr, const QString& viewName = {}): QTableView(parent), m_viewName(viewName) {
		auto* hh = horizontalHeader();
		hh->setStretchLastSection(true);
		hh->setSectionResizeMode(QHeaderView::Interactive);
		hh->setSectionsMovable(true);
		hh->setSectionsClickable(true);
		hh->setSortIndicatorShown(true);
		hh->setSortIndicator(0, Qt::AscendingOrder);
		hh->setContextMenuPolicy(Qt::CustomContextMenu);
		connect(hh, &QHeaderView::customContextMenuRequested, this,
                [this, hh](const QPoint& p) {
                    QMenu menu(hh);
                    QAction* reset = menu.addAction(tr("Reset Column Layout"));
                    connect(reset, &QAction::triggered, this, &TableViewBase::resetColumnLayout);
                    populateHeaderContextMenu(&menu, p);
                    menu.exec(hh->viewport()->mapToGlobal(p));
                });

		m_headerSaveDebounce.setSingleShot(true);
		m_headerSaveDebounce.setInterval(150);

		connect(&m_headerSaveDebounce, &QTimer::timeout, this, &TableViewBase::saveHeaderState);
		connect(hh, &QHeaderView::sectionResized, this, &TableViewBase::scheduleSaveHeaderState);
		connect(hh, &QHeaderView::sectionMoved, this, &TableViewBase::scheduleSaveHeaderState);

		setShowGrid(false);
		setSortingEnabled(true);

		QMetaObject::invokeMethod(this, "restoreHeaderState", Qt::QueuedConnection);
	}


	void setModel(QAbstractItemModel* m) override
    {
        QTableView::setModel(m);
        if (!m) return;
        connect(m, &QAbstractItemModel::modelReset,      this, &TableViewBase::restoreHeaderState);
        connect(m, &QAbstractItemModel::columnsInserted, this, &TableViewBase::restoreHeaderState);
        connect(m, &QAbstractItemModel::columnsRemoved,  this, &TableViewBase::restoreHeaderState);

		// Grab default header state
		QTimer::singleShot(0, this, [this]{
		    captureDefaultHeaderState();
		});

        QMetaObject::invokeMethod(this, "restoreHeaderState", Qt::QueuedConnection);
    }

	// Save after debounce for repeated move/drag
	void scheduleSaveHeaderState() { m_headerSaveDebounce.start(); }

Q_SIGNALS:
    // For owners/derived classes to add their own menu items
	void populateHeaderContextMenu(QMenu*, const QPoint&);

protected:
	QString viewName() const {
        if (!m_viewName.isEmpty()) return m_viewName;
        if (!objectName().isEmpty()) return objectName();
        return metaObject()->className();
    }

    QString settingsKey(const QString& suffix) const {
        return QStringLiteral("tables/%1/%2").arg(viewName(), suffix);
    }

    void saveHeaderState() const {
		auto* hh = horizontalHeader();
        if (!hh) return;
        QSettings s;
        s.setValue(settingsKey("horizontalHeaderState"), hh->saveState());
    }

    void restoreHeaderState() const
    {
		auto* hh = horizontalHeader();
        if (!hh) return;
        QSettings s;
        const QByteArray st = s.value(settingsKey("horizontalHeaderState")).toByteArray();
        if (!st.isEmpty()) hh->restoreState(st);

		const QByteArray def = s.value(settingsKey("horizontalHeaderDefaultState")).toByteArray();
		if (!def.isEmpty()) hh->restoreState(def);
    }

	virtual int defaultSectionWidth(const int logicalIndex, const int charWidth) const
    {
        QString headerText;
        if (model()) {
            headerText = model()->headerData(logicalIndex, Qt::Horizontal, Qt::DisplayRole).toString();
        }
        constexpr int minChars = 8;
        const int headerChars = qMax(minChars, headerText.size() + 2);
        return headerChars * charWidth;
    }

	/// Grabs default header states on startup to save
	/// Kind of a hacky fix, but many of our tables have manually set widths,
	/// so compensating for them is a hassle.
	void captureDefaultHeaderState() const
	{
		auto* hh = horizontalHeader();
		if (!hh) return;

		QSettings s;
		const auto key = settingsKey("horizontalHeaderDefaultState");
		if (!s.contains(key)) {
			s.setValue(key, hh->saveState());
			s.sync();
		}
	}


	void resetColumnLayout() const
	{
		auto* hh = horizontalHeader();
		if (!hh || !model()) return;

		{
			QSettings s;
			s.remove(settingsKey("horizontalHeaderState"));
		}

		QSettings s;
		const QByteArray def = s.value(settingsKey("horizontalHeaderDefaultState")).
			toByteArray();
		if (!def.isEmpty() && hh->restoreState(def))
		{
			return;
		}

		// If no default or set user layout, use size hints
		for (int c = 0; c < model()->columnCount(); ++c)
		{
			constexpr int extra = 12;
			int w = sizeHintForColumn(c);
			QVariant head = model()->headerData(c, Qt::Horizontal, Qt::SizeHintRole);
			int headerW = hh->sectionSizeHint(c);
			if (head.canConvert<QSize>())
				headerW = std::max(headerW, head.toSize().width());
			hh->resizeSection(c, std::max(w, headerW) + extra);
		}
	}


private:
	QString m_viewName;
	QTimer m_headerSaveDebounce;

};
