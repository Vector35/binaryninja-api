#pragma once

#include "core/binaryninja_defs.h"

extern "C" {
	struct BNBinaryView;
	struct BNReportCollection;
	struct BNFlowGraph;

	enum BNMessageBoxIcon
	{
		InformationIcon,
		QuestionIcon,
		WarningIcon,
		ErrorIcon
	};

	enum BNMessageBoxButtonSet
	{
		OKButtonSet,
		YesNoButtonSet,
		YesNoCancelButtonSet
	};

	enum BNMessageBoxButtonResult
	{
		NoButton = 0,
		YesButton = 1,
		OKButton = 2,
		CancelButton = 3
	};

	enum BNFormInputFieldType
	{
		LabelFormField,
		SeparatorFormField,
		TextLineFormField,
		MultilineTextFormField,
		IntegerFormField,
		AddressFormField,
		ChoiceFormField,
		OpenFileNameFormField,
		SaveFileNameFormField,
		DirectoryNameFormField
	};

	enum BNReportType
	{
		PlainTextReportType,
		MarkdownReportType,
		HTMLReportType,
		FlowGraphReportType
	};

	struct BNFormInputField
	{
		BNFormInputFieldType type;
		const char* prompt;
		BNBinaryView* view;       // For AddressFormField
		uint64_t currentAddress;  // For AddressFormField
		const char** choices;     // For ChoiceFormField
		size_t count;             // For ChoiceFormField
		const char* ext;          // For OpenFileNameFormField, SaveFileNameFormField
		const char* defaultName;  // For SaveFileNameFormField
		int64_t intResult;
		uint64_t addressResult;
		char* stringResult;
		size_t indexResult;
		bool hasDefault;
		int64_t intDefault;
		uint64_t addressDefault;
		const char* stringDefault;
		size_t indexDefault;
	};

	struct BNInteractionHandlerCallbacks
	{
		void* context;
		void (*showPlainTextReport)(void* ctxt, BNBinaryView* view, const char* title, const char* contents);
		void (*showMarkdownReport)(
			void* ctxt, BNBinaryView* view, const char* title, const char* contents, const char* plaintext);
		void (*showHTMLReport)(
			void* ctxt, BNBinaryView* view, const char* title, const char* contents, const char* plaintext);
		void (*showGraphReport)(void* ctxt, BNBinaryView* view, const char* title, BNFlowGraph* graph);
		void (*showReportCollection)(void* ctxt, const char* title, BNReportCollection* reports);
		bool (*getTextLineInput)(void* ctxt, char** result, const char* prompt, const char* title);
		bool (*getIntegerInput)(void* ctxt, int64_t* result, const char* prompt, const char* title);
		bool (*getAddressInput)(void* ctxt, uint64_t* result, const char* prompt, const char* title, BNBinaryView* view,
			uint64_t currentAddr);
		bool (*getChoiceInput)(
			void* ctxt, size_t* result, const char* prompt, const char* title, const char** choices, size_t count);
		bool (*getOpenFileNameInput)(void* ctxt, char** result, const char* prompt, const char* ext);
		bool (*getSaveFileNameInput)(
			void* ctxt, char** result, const char* prompt, const char* ext, const char* defaultName);
		bool (*getDirectoryNameInput)(void* ctxt, char** result, const char* prompt, const char* defaultName);
		bool (*getFormInput)(void* ctxt, BNFormInputField* fields, size_t count, const char* title);
		BNMessageBoxButtonResult (*showMessageBox)(
			void* ctxt, const char* title, const char* text, BNMessageBoxButtonSet buttons, BNMessageBoxIcon icon);
		bool (*openUrl)(void* ctxt, const char* url);
	};

	// Interaction APIs
	BINARYNINJACOREAPI void BNRegisterInteractionHandler(BNInteractionHandlerCallbacks* callbacks);
	BINARYNINJACOREAPI char* BNMarkdownToHTML(const char* contents);
	BINARYNINJACOREAPI void BNShowPlainTextReport(BNBinaryView* view, const char* title, const char* contents);
	BINARYNINJACOREAPI void BNShowMarkdownReport(
		BNBinaryView* view, const char* title, const char* contents, const char* plaintext);
	BINARYNINJACOREAPI void BNShowHTMLReport(
		BNBinaryView* view, const char* title, const char* contents, const char* plaintext);
	BINARYNINJACOREAPI void BNShowGraphReport(BNBinaryView* view, const char* title, BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNShowReportCollection(const char* title, BNReportCollection* reports);
	BINARYNINJACOREAPI bool BNGetTextLineInput(char** result, const char* prompt, const char* title);
	BINARYNINJACOREAPI bool BNGetIntegerInput(int64_t* result, const char* prompt, const char* title);
	BINARYNINJACOREAPI bool BNGetAddressInput(
		uint64_t* result, const char* prompt, const char* title, BNBinaryView* view, uint64_t currentAddr);
	BINARYNINJACOREAPI bool BNGetChoiceInput(
		size_t* result, const char* prompt, const char* title, const char** choices, size_t count);
	BINARYNINJACOREAPI bool BNGetOpenFileNameInput(char** result, const char* prompt, const char* ext);
	BINARYNINJACOREAPI bool BNGetSaveFileNameInput(
		char** result, const char* prompt, const char* ext, const char* defaultName);
	BINARYNINJACOREAPI bool BNGetDirectoryNameInput(char** result, const char* prompt, const char* defaultName);
	BINARYNINJACOREAPI bool BNGetFormInput(BNFormInputField* fields, size_t count, const char* title);
	BINARYNINJACOREAPI void BNFreeFormInputResults(BNFormInputField* fields, size_t count);
	BINARYNINJACOREAPI BNMessageBoxButtonResult BNShowMessageBox(
		const char* title, const char* text, BNMessageBoxButtonSet buttons, BNMessageBoxIcon icon);
	BINARYNINJACOREAPI bool BNOpenUrl(const char* url);

	BINARYNINJACOREAPI BNReportCollection* BNCreateReportCollection(void);
	BINARYNINJACOREAPI BNReportCollection* BNNewReportCollectionReference(BNReportCollection* reports);
	BINARYNINJACOREAPI void BNFreeReportCollection(BNReportCollection* reports);
	BINARYNINJACOREAPI size_t BNGetReportCollectionCount(BNReportCollection* reports);
	BINARYNINJACOREAPI BNReportType BNGetReportType(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI BNBinaryView* BNGetReportView(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI char* BNGetReportTitle(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI char* BNGetReportContents(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI char* BNGetReportPlainText(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI BNFlowGraph* BNGetReportFlowGraph(BNReportCollection* reports, size_t i);
	BINARYNINJACOREAPI void BNAddPlainTextReportToCollection(
		BNReportCollection* reports, BNBinaryView* view, const char* title, const char* contents);
	BINARYNINJACOREAPI void BNAddMarkdownReportToCollection(BNReportCollection* reports, BNBinaryView* view,
		const char* title, const char* contents, const char* plaintext);
	BINARYNINJACOREAPI void BNAddHTMLReportToCollection(BNReportCollection* reports, BNBinaryView* view,
		const char* title, const char* contents, const char* plaintext);
	BINARYNINJACOREAPI void BNAddGraphReportToCollection(
		BNReportCollection* reports, BNBinaryView* view, const char* title, BNFlowGraph* graph);
	BINARYNINJACOREAPI void BNUpdateReportFlowGraph(BNReportCollection* reports, size_t i, BNFlowGraph* graph);
}