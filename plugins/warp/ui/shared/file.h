#pragma once

#include <QWidget>
#include <QListWidget>
#include <QSplitter>
#include "warp.h"
#include "chunk.h"

class FileWidget : public QWidget
{
	Q_OBJECT

public:
	explicit FileWidget(QWidget* parent = nullptr);
	void setFile(Warp::Ref<Warp::File> file);

private slots:
	void onListSelectionChanged();

private:
	Warp::Ref<Warp::File> m_file;
	QListWidget* m_list;
	ChunkWidget* m_chunkWidget;
	std::vector<Warp::Ref<Warp::Chunk>> m_currentChunks;
};