#pragma once

#include <QDialog>
#include <QComboBox>
#include <QListWidget>
#include <QSpinBox>
#include <QCheckBox>

#include "uicontext.h"
#include "viewframe.h"
#include "warp.h"
#include "fetcher.h"

class WarpFetchDialog : public QDialog
{
    Q_OBJECT

    QComboBox *m_containerCombo;

    QListWidget *m_tagsList;
    QPushButton *m_addTagBtn;
    QPushButton *m_removeTagBtn;

    QSpinBox *m_batchSize;
    QCheckBox *m_rerunMatcher;
    QCheckBox *m_clearProcessed;

    std::vector<Warp::Ref<Warp::Container> > m_containers;

    std::shared_ptr<WarpFetcher> m_fetchProcessor;
    BinaryViewRef m_bv;

public:
    explicit WarpFetchDialog(BinaryViewRef bv,
                             std::shared_ptr<WarpFetcher> fetchProcessor,
                             QWidget *parent = nullptr);

private slots:
    void onAddTag();

    void onRemoveTag();

    void onAccept();

private:
    void populateContainers();

    std::vector<Warp::SourceTag> collectTags() const;

    void runBatchedFetch(const std::optional<size_t> &containerIndex,
                         const std::vector<Warp::SourceTag> &tags,
                         size_t batchSize,
                         bool rerunMatcher);
};

void RegisterWarpFetchFunctionsCommand();
