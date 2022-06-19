#pragma once

#include <vector>
#include <string>
#include "refcount.hpp"
#include "core/interaction.h"

namespace BinaryNinja {
    class BinaryView;
    class FlowGraph;

	struct FormInputField
	{
		BNFormInputFieldType type;
		std::string prompt;
		Ref<BinaryView> view;              // For AddressFormField
		uint64_t currentAddress;           // For AddressFormField
		std::vector<std::string> choices;  // For ChoiceFormField
		std::string ext;                   // For OpenFileNameFormField, SaveFileNameFormField
		std::string defaultName;           // For SaveFileNameFormField
		int64_t intResult;
		uint64_t addressResult;
		std::string stringResult;
		size_t indexResult;
		bool hasDefault;
		int64_t intDefault;
		uint64_t addressDefault;
		std::string stringDefault;
		size_t indexDefault;

		static FormInputField Label(const std::string& text);
		static FormInputField Separator();
		static FormInputField TextLine(const std::string& prompt);
		static FormInputField MultilineText(const std::string& prompt);
		static FormInputField Integer(const std::string& prompt);
		static FormInputField Address(
		    const std::string& prompt, BinaryView* view = nullptr, uint64_t currentAddress = 0);
		static FormInputField Choice(const std::string& prompt, const std::vector<std::string>& choices);
		static FormInputField OpenFileName(const std::string& prompt, const std::string& ext);
		static FormInputField SaveFileName(
		    const std::string& prompt, const std::string& ext, const std::string& defaultName = "");
		static FormInputField DirectoryName(const std::string& prompt, const std::string& defaultName = "");
	};

	class ReportCollection :
	    public CoreRefCountObject<BNReportCollection, BNNewReportCollectionReference, BNFreeReportCollection>
	{
	  public:
		ReportCollection();
		ReportCollection(BNReportCollection* reports);

		size_t GetCount() const;
		BNReportType GetType(size_t i) const;
		Ref<BinaryView> GetView(size_t i) const;
		std::string GetTitle(size_t i) const;
		std::string GetContents(size_t i) const;
		std::string GetPlainText(size_t i) const;
		Ref<FlowGraph> GetFlowGraph(size_t i) const;

		void AddPlainTextReport(Ref<BinaryView> view, const std::string& title, const std::string& contents);
		void AddMarkdownReport(Ref<BinaryView> view, const std::string& title, const std::string& contents,
		    const std::string& plainText = "");
		void AddHTMLReport(Ref<BinaryView> view, const std::string& title, const std::string& contents,
		    const std::string& plainText = "");
		void AddGraphReport(Ref<BinaryView> view, const std::string& title, Ref<FlowGraph> graph);

		void UpdateFlowGraph(size_t i, Ref<FlowGraph> graph);
	};

	class InteractionHandler
	{
	  public:
		virtual void ShowPlainTextReport(
		    Ref<BinaryView> view, const std::string& title, const std::string& contents) = 0;
		virtual void ShowMarkdownReport(
		    Ref<BinaryView> view, const std::string& title, const std::string& contents, const std::string& plainText);
		virtual void ShowHTMLReport(
		    Ref<BinaryView> view, const std::string& title, const std::string& contents, const std::string& plainText);
		virtual void ShowGraphReport(Ref<BinaryView> view, const std::string& title, Ref<FlowGraph> graph);
		virtual void ShowReportCollection(const std::string& title, Ref<ReportCollection> reports);

		virtual bool GetTextLineInput(std::string& result, const std::string& prompt, const std::string& title) = 0;
		virtual bool GetIntegerInput(int64_t& result, const std::string& prompt, const std::string& title);
		virtual bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title,
		    Ref<BinaryView> view, uint64_t currentAddr);
		virtual bool GetChoiceInput(size_t& idx, const std::string& prompt, const std::string& title,
		    const std::vector<std::string>& choices) = 0;
		virtual bool GetOpenFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "");
		virtual bool GetSaveFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "",
		    const std::string& defaultName = "");
		virtual bool GetDirectoryNameInput(
		    std::string& result, const std::string& prompt, const std::string& defaultName = "");
		virtual bool GetFormInput(std::vector<FormInputField>& fields, const std::string& title) = 0;

		virtual BNMessageBoxButtonResult ShowMessageBox(const std::string& title, const std::string& text,
		    BNMessageBoxButtonSet buttons = OKButtonSet, BNMessageBoxIcon icon = InformationIcon) = 0;
		virtual bool OpenUrl(const std::string& url) = 0;
	};


	void ShowPlainTextReport(const std::string& title, const std::string& contents);
	void ShowMarkdownReport(const std::string& title, const std::string& contents, const std::string& plainText = "");
	void ShowHTMLReport(const std::string& title, const std::string& contents, const std::string& plainText = "");
	void ShowGraphReport(const std::string& title, FlowGraph* graph);
	void ShowReportCollection(const std::string& title, ReportCollection* reports);

	bool GetTextLineInput(std::string& result, const std::string& prompt, const std::string& title);
	bool GetIntegerInput(int64_t& result, const std::string& prompt, const std::string& title);
	bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);
	bool GetChoiceInput(
	    size_t& idx, const std::string& prompt, const std::string& title, const std::vector<std::string>& choices);
	bool GetOpenFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "");
	bool GetSaveFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "",
	    const std::string& defaultName = "");
	bool GetDirectoryNameInput(std::string& result, const std::string& prompt, const std::string& defaultName = "");
	bool GetFormInput(std::vector<FormInputField>& fields, const std::string& title);

	BNMessageBoxButtonResult ShowMessageBox(const std::string& title, const std::string& text,
	    BNMessageBoxButtonSet buttons = OKButtonSet, BNMessageBoxIcon icon = InformationIcon);

	bool OpenUrl(const std::string& url);
	void RegisterInteractionHandler(InteractionHandler* handler);
	std::string MarkdownToHTML(const std::string& contents);

}