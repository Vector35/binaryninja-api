#include "chunk.h"

#include <QAction>
#include <QClipboard>
#include <QGuiApplication>
#include <QHeaderView>
#include <QMenu>
#include <QVBoxLayout>

#include "misc.h"

ChunkWidget::ChunkWidget(QWidget* parent) : QWidget(parent)
{
	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(4);

	// Search Box
	m_searchBox = new QLineEdit(this);
	m_searchBox->setPlaceholderText("Search chunk contents...");
	m_searchBox->setClearButtonEnabled(true);
	connect(m_searchBox, &QLineEdit::textChanged, this, &ChunkWidget::onSearchTextChanged);
	layout->addWidget(m_searchBox);

	m_countLabel = new QLabel(this);
	m_countLabel->setContentsMargins(4, 0, 4, 0);
	layout->addWidget(m_countLabel);

	// Table Widget (Styled as a list)
	m_table = new QTableWidget(this);
	m_table->setColumnCount(3);
	m_table->setHorizontalHeaderLabels({"Type", "Name", "ID"});
	m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
	m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
	m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
	m_table->setItemDelegateForColumn(1, new TokenDataDelegate(this));
	m_table->setColumnHidden(2, true);

	// Visual tweaks to make it look like a nice list
	m_table->verticalHeader()->setVisible(false);
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setSelectionMode(QAbstractItemView::SingleSelection);
	m_table->setShowGrid(false);
	m_table->setAlternatingRowColors(false);
	m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_table->setStyleSheet("QTableWidget::item { padding: 10px; }");

	layout->addWidget(m_table);
}

void ChunkWidget::setChunk(Warp::Ref<Warp::Chunk> chunk)
{
	m_chunk = chunk;
	m_searchBox->clear();
	populateTable();
}

void ChunkWidget::populateTable()
{
	m_table->setRowCount(0);
	if (!m_chunk)
	{
		updateCountLabel();
		return;
	}

	auto functions = m_chunk->GetFunctions();
	auto types = m_chunk->GetTypes();

	m_table->setRowCount(functions.size() + types.size());
	int row = 0;

	for (const auto& func : functions)
	{
		m_table->setItem(row, 0, new QTableWidgetItem("Function"));

		auto* nameItem = new QTableWidgetItem();
		std::string symbolName = func->GetSymbolName();
		TokenData tokenData(symbolName);

		if (auto warpType = func->GetType())
		{
			if (auto analysisType = warpType->GetAnalysisType())
				tokenData = TokenData(*analysisType, symbolName);
		}

		nameItem->setText(QString::fromStdString(symbolName));  // Fallback text for search
		nameItem->setData(Qt::UserRole, QVariant::fromValue(tokenData));
		m_table->setItem(row, 1, nameItem);

		auto* idItem = new QTableWidgetItem(QString::fromStdString(func->GetGUID().ToString()));
		m_table->setItem(row, 2, idItem);

		row++;
	}

	for (const auto& type : types)
	{
		m_table->setItem(row, 0, new QTableWidgetItem("Type"));

		auto* nameItem = new QTableWidgetItem();
		std::string typeName = type->GetName().value_or("");
		TokenData tokenData(typeName);

		if (auto analysisType = type->GetAnalysisType())
		{
			tokenData = TokenData(*analysisType, typeName);
		}

		nameItem->setText(QString::fromStdString(typeName));  // Fallback text for search
		nameItem->setData(Qt::UserRole, QVariant::fromValue(tokenData));
		m_table->setItem(row, 1, nameItem);

		m_table->setItem(row, 2, new QTableWidgetItem(""));

		row++;
	}

	updateCountLabel();
}

void ChunkWidget::onSearchTextChanged(const QString& text)
{
	for (int i = 0; i < m_table->rowCount(); ++i)
	{
		bool match = false;
		for (int j = 0; j < m_table->columnCount(); ++j)
		{
			auto* item = m_table->item(i, j);
			if (item && item->text().contains(text, Qt::CaseInsensitive))
			{
				match = true;
				break;
			}
		}
		m_table->setRowHidden(i, !match);
	}
	updateCountLabel();
}

void ChunkWidget::updateCountLabel()
{
	int totalCount = m_table->rowCount();
	int visibleCount = 0;
	for (int i = 0; i < totalCount; ++i)
	{
		if (!m_table->isRowHidden(i))
			visibleCount++;
	}

	if (m_searchBox->text().isEmpty())
	{
		m_countLabel->setText(QString::number(totalCount) + " items");
	}
	else
	{
		m_countLabel->setText(QString::number(visibleCount) + " of " + QString::number(totalCount) + " items");
	}
}