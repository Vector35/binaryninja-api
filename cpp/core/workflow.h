#pragma once

#include "core/binaryninja_defs.h"
extern "C" {
	struct BNWorkflow;
	struct BNActivity;
	struct BNFlowGraph;
	// Workflow
	BINARYNINJACOREAPI BNWorkflow* BNCreateWorkflow(const char* name);
	BINARYNINJACOREAPI BNWorkflow* BNNewWorkflowReference(BNWorkflow* workflow);
	BINARYNINJACOREAPI void BNFreeWorkflow(BNWorkflow* workflow);

	BINARYNINJACOREAPI BNWorkflow** BNGetWorkflowList(size_t* count);
	BINARYNINJACOREAPI void BNFreeWorkflowList(BNWorkflow** workflows, size_t count);
	BINARYNINJACOREAPI BNWorkflow* BNWorkflowInstance(const char* name);
	BINARYNINJACOREAPI bool BNRegisterWorkflow(BNWorkflow* workflow, const char* description);

	BINARYNINJACOREAPI BNWorkflow* BNWorkflowClone(BNWorkflow* workflow, const char* name, const char* activity);
	BINARYNINJACOREAPI bool BNWorkflowRegisterActivity(
		BNWorkflow* workflow, BNActivity* activity, const char** subactivities, size_t size, const char* description);

	BINARYNINJACOREAPI bool BNWorkflowContains(BNWorkflow* workflow, const char* activity);
	BINARYNINJACOREAPI char* BNWorkflowGetConfiguration(BNWorkflow* workflow, const char* activity);
	BINARYNINJACOREAPI char* BNGetWorkflowName(BNWorkflow* workflow);
	BINARYNINJACOREAPI bool BNWorkflowIsRegistered(BNWorkflow* workflow);
	BINARYNINJACOREAPI size_t BNWorkflowSize(BNWorkflow* workflow);

	BINARYNINJACOREAPI BNActivity* BNWorkflowGetActivity(BNWorkflow* workflow, const char* activity);
	BINARYNINJACOREAPI const char** BNWorkflowGetActivityRoots(
		BNWorkflow* workflow, const char* activity, size_t* inoutSize);
	BINARYNINJACOREAPI const char** BNWorkflowGetSubactivities(
		BNWorkflow* workflow, const char* activity, bool immediate, size_t* inoutSize);
	BINARYNINJACOREAPI bool BNWorkflowAssignSubactivities(
		BNWorkflow* workflow, const char* activity, const char** activities, size_t size);
	BINARYNINJACOREAPI bool BNWorkflowClear(BNWorkflow* workflow);
	BINARYNINJACOREAPI bool BNWorkflowInsert(
		BNWorkflow* workflow, const char* activity, const char** activities, size_t size);
	BINARYNINJACOREAPI bool BNWorkflowRemove(BNWorkflow* workflow, const char* activity);
	BINARYNINJACOREAPI bool BNWorkflowReplace(BNWorkflow* workflow, const char* activity, const char* newActivity);

	BINARYNINJACOREAPI BNFlowGraph* BNWorkflowGetGraph(BNWorkflow* workflow, const char* activity, bool sequential);
	BINARYNINJACOREAPI void BNWorkflowShowReport(BNWorkflow* workflow, const char* name);

	// BINARYNINJACOREAPI bool BNWorkflowRun(const char* activity, BNAnalysisContext* analysisContext);
}