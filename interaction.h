#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace BinaryNinja
{
	class BinaryView;
	class FlowGraph;
	class ReportCollection;


	/*!
		\ingroup interaction
	*/
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

	/*!
		\ingroup interaction
	*/
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
		virtual bool GetLargeChoiceInput(size_t& idx, const std::string& prompt, const std::string& title,
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
		virtual bool RunProgressDialog(const std::string& title, bool canCancel, std::function<void(std::function<bool(size_t, size_t)> progress)> task) = 0;
	};

	void RegisterInteractionHandler(InteractionHandler* handler);

	/*! Displays contents to the user in the UI or on the command-line

		@threadsafe

		\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
		the command line, a simple text prompt is used.

	 	\ingroup interaction

		\param title Title for the report
		\param contents Contents of the report
	*/
	void ShowPlainTextReport(const std::string& title, const std::string& contents);

	/*! Displays markdown contents to the user in the UI or on the command-line

		@threadsafe

	 	\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
		the command line, a simple text prompt is used.

	 	\ingroup interaction

		\param title Title for the report
		\param contents Markdown contents of the report
		\param plainText Plaintext contents of the report (used on the command line)
	*/
	void ShowMarkdownReport(const std::string& title, const std::string& contents, const std::string& plainText = "");

	/*! Displays HTML contents to the user in the UI or on the command-line

		@threadsafe

		\note This API functions differently on the command-line vs the UI. In the UI, it will be rendered in a new tab. From
		the command line, a simple text prompt is used.
		\note This API doesn't support clickable references into an existing BinaryView.

	 	\ingroup interaction

		\param title Title for the report
		\param contents HTML contents of the report
		\param plainText Plaintext contents of the report (used on the command line)
	*/
	void ShowHTMLReport(const std::string& title, const std::string& contents, const std::string& plainText = "");

	/*! Displays a flow graph in UI applications and nothing in command-line applications.

		@threadsafe

	 	\note This API doesn't support clickable references into an existing BinaryView.
	 	\note This API has no effect outside of the UI

	 	\ingroup interaction

		\param title Title for the report
		\param graph FlowGraph object to be rendered.
	*/
	void ShowGraphReport(const std::string& title, FlowGraph* graph);

	/*! Show a collection of reports

		@threadsafe

	 	\ingroup interaction

		\param title Title for the collection of reports
		\param reports Collection of reports to show
	*/
	void ShowReportCollection(const std::string& title, ReportCollection* reports);

	/*! Prompts the user to input a string with the given prompt and title

		@threadsafe

	 	\ingroup interaction

		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\return Whether a line was successfully received
	*/
	bool GetTextLineInput(std::string& result, const std::string& prompt, const std::string& title);

	/*! Prompts the user to input an integer with the given prompt and title

		@threadsafe

	 	\ingroup interaction
		\param[out] result Reference to the int64_t the result will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\return Whether an integer was successfully received
	*/
	bool GetIntegerInput(int64_t& result, const std::string& prompt, const std::string& title);

	/*! Prompts the user to input an unsigned integer with the given prompt and title

		@threadsafe

	 	\ingroup interaction
		\param[out] result Reference to the uint64_t the result will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\return Whether an integer was successfully received
	*/
	bool GetAddressInput(uint64_t& result, const std::string& prompt, const std::string& title);

	/*! Prompts the user to select the one of the provided choices

		@threadsafe

	 	\ingroup interaction
		\param[out] idx Reference to the size_t the resulting index selected will be copied to
		\param[in] prompt Prompt for the input
		\param[in] title Title for the input popup when used in UI
		\param[in] choices List of string choices for the user to select from
		\return Whether a choice was successfully picked
	*/
	bool GetChoiceInput(
		size_t& idx, const std::string& prompt, const std::string& title, const std::vector<std::string>& choices);

	/*! Prompts the user to select the one of the provided choices out of a large list, with the option to filter choices

		\ingroup interaction
		\param[out] idx Reference to the size_t the resulting index selected will be copied to
		\param[in] title Title for the input popup / prompt for headless
		\param[in] prompt Prompt for the input (shown on the 'Select' button in UI)
		\param[in] choices List of string choices for the user to select from
		\return Whether a choice was successfully picked
	*/
	bool GetLargeChoiceInput(size_t& idx, const std::string& title, const std::string& prompt, const std::vector<std::string>& choices);

	/*! Prompts the user for a file name to open

		@threadsafe

		Multiple file selection groups can be included if separated by two semicolons. Multiple file wildcards may be
	 	specified by using a space within the parenthesis.

		Also, a simple selector of "\*.extension" by itself may also be used instead of specifying the description.

	 	\ingroup interaction

		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the dialog
		\param[in] ext Optional, file extension
		\return Whether a filename was successfully received
	*/
	bool GetOpenFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "");

	/*! Prompts the user for a file name to save as, optionally providing a file extension and defaultName

		@threadsafe

	 	\ingroup interaction

		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the dialog
		\param[in] ext Optional, file extension
		\param[in] defaultName Optional, default filename
		\return Whether a filename was successfully received
	*/
	bool GetSaveFileNameInput(std::string& result, const std::string& prompt, const std::string& ext = "",
	    const std::string& defaultName = "");

	/*! Prompts the user for a directory name to save as, optionally providing a default_name

		@threadsafe

	 	\ingroup interaction
		\param[out] result Reference to the string the result will be copied to
		\param[in] prompt Prompt for the dialog
		\param[in] defaultName Optional, default directory name
		\return Whether a directory was successfully received
	*/
	bool GetDirectoryNameInput(std::string& result, const std::string& prompt, const std::string& defaultName = "");

	/*! Prompts the user for a set of inputs specified in `fields` with given title.
		The fields parameter is a list containing FieldInputFields

		@threadsafe

	 	\ingroup interaction
		\param[in,out] fields reference to a list containing FieldInputFields
		\param[in] title Title of the Form
		\return Whether the form was successfully filled out
	*/
	bool GetFormInput(std::vector<FormInputField>& fields, const std::string& title);

	/*! Displays a configurable message box in the UI, or prompts on the console as appropriate

		@threadsafe

		\param title Title for the message box
		\param text Contents of the message box
		\param buttons
	 	\parblock
	    Button Set type to display to the user

	    	OKButtonSet - Displays only an OK button
	    	YesNoButtonSet - Displays a Yes and a No button
	    	YesNoCancelButtonSet - Displays a Yes, No, and Cancel button
	    \endparblock
		\param icon Icons to display to the user

	 	\ingroup interaction

		\return Which button was selected'
	 	\retval NoButton No was clicked, or the box was closed and had type YesNoButtonSet
	 	\retval YesButton Yes was clicked
	 	\retval OKButton Ok Button was clicked, or the box was closed and had type OKButtonSet
	 	\retval CancelButton Cancel button was clicked or the dialog box was closed and had type YesNoCancelButtonSet
	*/
	BNMessageBoxButtonResult ShowMessageBox(const std::string& title, const std::string& text,
	    BNMessageBoxButtonSet buttons = OKButtonSet, BNMessageBoxIcon icon = InformationIcon);

	/*! Opens a given url in the user's web browser, if available.

		@threadsafe

	 	\ingroup interaction

		\param url URL to open
		\return Whether a URL was successfully opened.
	*/
	bool OpenUrl(const std::string& url);
}
