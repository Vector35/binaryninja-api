#pragma once

#include <QWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QLabel>
#include "warp.h"

class ChunkWidget : public QWidget
{
	Q_OBJECT

public:
	explicit ChunkWidget(QWidget* parent = nullptr);
	void setChunk(Warp::Ref<Warp::Chunk> chunk);

private slots:
	void onSearchTextChanged(const QString& text);

private:
	void populateTable();
	void updateCountLabel();

	Warp::Ref<Warp::Chunk> m_chunk;
	QLineEdit* m_searchBox;
	QLabel* m_countLabel;
	QTableWidget* m_table;
};