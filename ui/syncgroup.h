#pragma once

#include "viewframe.h"
#include "clickablelabel.h"

class BINARYNINJAUIAPI SyncGroup
{
	std::set<ViewFrame*> m_members;
	ViewFrame* m_lastSyncFrame = nullptr;
	int m_id;

  public:
	SyncGroup(int id);

	void addMember(ViewFrame* frame);
	void removeMember(ViewFrame* frame);
	void replaceMember(ViewFrame* oldFrame, ViewFrame* newFrame);
	bool isEmpty() const;
	int identifier() const { return m_id; }
	bool contains(ViewFrame* frame) const;
	const std::set<ViewFrame*>& members() const { return m_members; }
	ViewFrame* lastSyncFrame() const { return m_lastSyncFrame; }

	void syncLocation(ViewFrame* frame, View* view, const ViewLocation& location);

	static void syncToTarget(View* srcView, ViewFrame* targetFrame, const ViewLocation& location);
};

class BINARYNINJAUIAPI SyncGroupWidget : public ClickableIcon
{
	Q_OBJECT

	ViewFrame* m_frame;

  public:
	SyncGroupWidget(ViewFrame* frame);

	void updateStatus();
	void setViewFrame(ViewFrame* frame);

  private Q_SLOTS:
	void handleClick();
};
