#include <stdlib.h>
#include <string.h>
#include "binaryview.h"

#include "interaction.hpp"
#include "refcount.hpp"
#include "function.hpp"
#include "flowgraph.hpp"
#include "getobject.hpp"

using namespace std;
using namespace BinaryNinja;


FormInputField FormInputField::Label(const string& text)
{
	FormInputField result;
	result.type = LabelFormField;
	result.prompt = text;
	result.hasDefault = false;
	return result;
}


FormInputField FormInputField::Separator()
{
	FormInputField result;
	result.type = SeparatorFormField;
	result.hasDefault = false;
	return result;
}


FormInputField FormInputField::TextLine(const string& prompt)
{
	FormInputField result;
	result.type = TextLineFormField;
	result.prompt = prompt;
	result.hasDefault = false;
	return result;
}


FormInputField FormInputField::MultilineText(const string& prompt)
{
	FormInputField result;
	result.type = MultilineTextFormField;
	result.prompt = prompt;
	result.hasDefault = false;
	return result;
}


FormInputField FormInputField::Integer(const string& prompt)
{
	FormInputField result;
	result.type = IntegerFormField;
	result.prompt = prompt;
	result.hasDefault = false;
	return result;
}


FormInputField FormInputField::Address(const std::string& prompt, BinaryView* view, uint64_t currentAddress)
{
	FormInputField result;
	result.type = AddressFormField;
	result.prompt = prompt;
	result.view = view;
	result.currentAddress = currentAddress;
	result.hasDefault = false;
	return result;
}


FormInputField FormInputField::Choice(const string& prompt, const vector<string>& choices)
{
	FormInputField result;
	result.type = ChoiceFormField;
	result.prompt = prompt;
	result.choices = choices;
	result.hasDefault = false;
	return result;
}


FormInputField FormInputField::OpenFileName(const string& prompt, const string& ext)
{
	FormInputField result;
	result.type = OpenFileNameFormField;
	result.prompt = prompt;
	result.ext = ext;
	result.hasDefault = false;
	return result;
}


FormInputField FormInputField::SaveFileName(const string& prompt, const string& ext, const string& defaultName)
{
	FormInputField result;
	result.type = SaveFileNameFormField;
	result.prompt = prompt;
	result.ext = ext;
	result.defaultName = defaultName;
	result.hasDefault = false;
	return result;
}


FormInputField FormInputField::DirectoryName(const string& prompt, const string& defaultName)
{
	FormInputField result;
	result.type = DirectoryNameFormField;
	result.prompt = prompt;
	result.defaultName = defaultName;
	result.hasDefault = false;
	return result;
}


void InteractionHandler::ShowMarkdownReport(
    Ref<BinaryView> view, const string& title, const string& contents, const string& plainText)
{
	(void)contents;
	if (plainText.size() != 0)
		ShowPlainTextReport(view, title, plainText);
}


void InteractionHandler::ShowHTMLReport(
    Ref<BinaryView> view, const string& title, const string&, const string& plainText)
{
	if (plainText.size() != 0)
		ShowPlainTextReport(view, title, plainText);
}


void InteractionHandler::ShowGraphReport(Ref<BinaryView>, const std::string&, Ref<FlowGraph>) {}


void InteractionHandler::ShowReportCollection(const string&, Ref<ReportCollection>) {}


bool InteractionHandler::GetIntegerInput(int64_t& result, const string& prompt, const string& title)
{
	while (true)
	{
		string input;
		if (!GetTextLineInput(input, prompt, title))
			return false;
		if (input.size() == 0)
			return false;

		errno = 0;
		result = strtoll(input.c_str(), nullptr, 0);
		if (errno != 0)
		{
			errno = 0;
			result = strtoull(input.c_str(), nullptr, 0);
			if (errno != 0)
				continue;
		}

		return true;
	}
}


bool InteractionHandler::GetAddressInput(
    uint64_t& result, const string& prompt, const string& title, Ref<BinaryView>, uint64_t)
{
	int64_t value;
	if (!GetIntegerInput(value, prompt, title))
		return false;
	result = (uint64_t)value;
	return true;
}


bool InteractionHandler::GetOpenFileNameInput(string& result, const string& prompt, const string&)
{
	return GetTextLineInput(result, prompt, "Open File");
}


bool InteractionHandler::GetSaveFileNameInput(string& result, const string& prompt, const string&, const string&)
{
	return GetTextLineInput(result, prompt, "Save File");
}


bool InteractionHandler::GetDirectoryNameInput(string& result, const string& prompt, const string&)
{
	return GetTextLineInput(result, prompt, "Select Directory");
}


static void ShowPlainTextReportCallback(void* ctxt, BNBinaryView* view, const char* title, const char* contents)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	handler->ShowPlainTextReport(view ? CreateNewReferencedView(view) : nullptr, title, contents);
}


static void ShowMarkdownReportCallback(
    void* ctxt, BNBinaryView* view, const char* title, const char* contents, const char* plaintext)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	handler->ShowMarkdownReport(view ? CreateNewReferencedView(view) : nullptr, title, contents, plaintext);
}


static void ShowHTMLReportCallback(
    void* ctxt, BNBinaryView* view, const char* title, const char* contents, const char* plaintext)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	handler->ShowHTMLReport(view ? CreateNewReferencedView(view) : nullptr, title, contents, plaintext);
}


static void ShowGraphReportCallback(void* ctxt, BNBinaryView* view, const char* title, BNFlowGraph* graph)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	handler->ShowGraphReport(view ? CreateNewReferencedView(view) : nullptr, title,
	    new CoreFlowGraph(BNNewFlowGraphReference(graph)));
}


static void ShowReportCollectionCallback(void* ctxt, const char* title, BNReportCollection* reports)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	handler->ShowReportCollection(title, new ReportCollection(BNNewReportCollectionReference(reports)));
}


static bool GetTextLineInputCallback(void* ctxt, char** result, const char* prompt, const char* title)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	string value;
	if (!handler->GetTextLineInput(value, prompt, title))
		return false;
	*result = BNAllocString(value.c_str());
	return true;
}


static bool GetIntegerInputCallback(void* ctxt, int64_t* result, const char* prompt, const char* title)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	return handler->GetIntegerInput(*result, prompt, title);
}


static bool GetAddressInputCallback(
    void* ctxt, uint64_t* result, const char* prompt, const char* title, BNBinaryView* view, uint64_t currentAddr)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	return handler->GetAddressInput(
	    *result, prompt, title, view ? CreateNewReferencedView(view) : nullptr, currentAddr);
}


static bool GetChoiceInputCallback(
    void* ctxt, size_t* result, const char* prompt, const char* title, const char** choices, size_t count)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	vector<string> choiceStrs;
	for (size_t i = 0; i < count; i++)
		choiceStrs.push_back(choices[i]);
	return handler->GetChoiceInput(*result, prompt, title, choiceStrs);
}


static bool GetOpenFileNameInputCallback(void* ctxt, char** result, const char* prompt, const char* ext)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	string value;
	if (!handler->GetOpenFileNameInput(value, prompt, ext))
		return false;
	*result = BNAllocString(value.c_str());
	return true;
}


static bool GetSaveFileNameInputCallback(
    void* ctxt, char** result, const char* prompt, const char* ext, const char* defaultName)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	string value;
	if (!handler->GetSaveFileNameInput(value, prompt, ext, defaultName))
		return false;
	*result = BNAllocString(value.c_str());
	return true;
}


static bool GetDirectoryNameInputCallback(void* ctxt, char** result, const char* prompt, const char* defaultName)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	string value;
	if (!handler->GetDirectoryNameInput(value, prompt, defaultName))
		return false;
	*result = BNAllocString(value.c_str());
	return true;
}


static bool GetFormInputCallback(void* ctxt, BNFormInputField* fieldBuf, size_t count, const char* title)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;

	// Convert list of fields from core structure to API structure
	vector<FormInputField> fields;
	for (size_t i = 0; i < count; i++)
	{
		vector<string> choices;
		switch (fieldBuf[i].type)
		{
		case SeparatorFormField:
			fields.push_back(FormInputField::Separator());
			break;
		case TextLineFormField:
			fields.push_back(FormInputField::TextLine(fieldBuf[i].prompt));
			break;
		case MultilineTextFormField:
			fields.push_back(FormInputField::MultilineText(fieldBuf[i].prompt));
			break;
		case IntegerFormField:
			fields.push_back(FormInputField::Integer(fieldBuf[i].prompt));
			break;
		case AddressFormField:
			fields.push_back(FormInputField::Address(fieldBuf[i].prompt,
			    fieldBuf[i].view ? CreateNewReferencedView(fieldBuf[i].view) : nullptr,
			    fieldBuf[i].currentAddress));
			break;
		case ChoiceFormField:
			for (size_t j = 0; j < fieldBuf[i].count; j++)
				choices.push_back(fieldBuf[i].choices[j]);
			fields.push_back(FormInputField::Choice(fieldBuf[i].prompt, choices));
			break;
		case OpenFileNameFormField:
			fields.push_back(FormInputField::OpenFileName(fieldBuf[i].prompt, fieldBuf[i].ext));
			break;
		case SaveFileNameFormField:
			fields.push_back(
			    FormInputField::SaveFileName(fieldBuf[i].prompt, fieldBuf[i].ext, fieldBuf[i].defaultName));
			break;
		case DirectoryNameFormField:
			fields.push_back(FormInputField::DirectoryName(fieldBuf[i].prompt, fieldBuf[i].defaultName));
			break;
		default:
			fields.push_back(FormInputField::Label(fieldBuf[i].prompt));
			break;
		}
		fields.back().hasDefault = fieldBuf[i].hasDefault;
		if (fieldBuf[i].hasDefault)
		{
			switch (fieldBuf[i].type)
			{
			case TextLineFormField:
			case MultilineTextFormField:
			case OpenFileNameFormField:
			case SaveFileNameFormField:
			case DirectoryNameFormField:
				fields.back().stringDefault = fieldBuf[i].stringDefault;
				break;
			case IntegerFormField:
				fields.back().intDefault = fieldBuf[i].intDefault;
				break;
			case AddressFormField:
				fields.back().addressDefault = fieldBuf[i].addressDefault;
				break;
			case ChoiceFormField:
				fields.back().indexDefault = fieldBuf[i].indexDefault;
				break;
			default:
				break;
			}
		}
	}

	if (!handler->GetFormInput(fields, title))
		return false;

	// Place results into core structure
	for (size_t i = 0; i < count; i++)
	{
		switch (fieldBuf[i].type)
		{
		case TextLineFormField:
		case MultilineTextFormField:
		case OpenFileNameFormField:
		case SaveFileNameFormField:
		case DirectoryNameFormField:
			fieldBuf[i].stringResult = BNAllocString(fields[i].stringResult.c_str());
			break;
		case IntegerFormField:
			fieldBuf[i].intResult = fields[i].intResult;
			break;
		case AddressFormField:
			fieldBuf[i].addressResult = fields[i].addressResult;
			break;
		case ChoiceFormField:
			fieldBuf[i].indexResult = fields[i].indexResult;
			break;
		default:
			break;
		}
	}
	return true;
}


static BNMessageBoxButtonResult ShowMessageBoxCallback(
    void* ctxt, const char* title, const char* text, BNMessageBoxButtonSet buttons, BNMessageBoxIcon icon)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	return handler->ShowMessageBox(title, text, buttons, icon);
}


static bool OpenUrlCallback(void* ctxt, const char* url)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	return handler->OpenUrl(url);
}


void BinaryNinja::RegisterInteractionHandler(InteractionHandler* handler)
{
	BNInteractionHandlerCallbacks cb;
	cb.context = handler;
	cb.showPlainTextReport = ShowPlainTextReportCallback;
	cb.showMarkdownReport = ShowMarkdownReportCallback;
	cb.showHTMLReport = ShowHTMLReportCallback;
	cb.showGraphReport = ShowGraphReportCallback;
	cb.showReportCollection = ShowReportCollectionCallback;
	cb.getTextLineInput = GetTextLineInputCallback;
	cb.getIntegerInput = GetIntegerInputCallback;
	cb.getAddressInput = GetAddressInputCallback;
	cb.getChoiceInput = GetChoiceInputCallback;
	cb.getOpenFileNameInput = GetOpenFileNameInputCallback;
	cb.getSaveFileNameInput = GetSaveFileNameInputCallback;
	cb.getDirectoryNameInput = GetDirectoryNameInputCallback;
	cb.getFormInput = GetFormInputCallback;
	cb.showMessageBox = ShowMessageBoxCallback;
	cb.openUrl = OpenUrlCallback;
	BNRegisterInteractionHandler(&cb);
}


string BinaryNinja::MarkdownToHTML(const string& contents)
{
	char* str = BNMarkdownToHTML(contents.c_str());
	string result = str;
	BNFreeString(str);
	return result;
}


void BinaryNinja::ShowPlainTextReport(const string& title, const string& contents)
{
	BNShowPlainTextReport(nullptr, title.c_str(), contents.c_str());
}


void BinaryNinja::ShowMarkdownReport(const string& title, const string& contents, const string& plainText)
{
	BNShowMarkdownReport(nullptr, title.c_str(), contents.c_str(), plainText.c_str());
}


void BinaryNinja::ShowHTMLReport(const string& title, const string& contents, const string& plainText)
{
	BNShowHTMLReport(nullptr, title.c_str(), contents.c_str(), plainText.c_str());
}


void BinaryNinja::ShowGraphReport(const string& title, FlowGraph* graph)
{
	Ref<Function> func = graph->GetFunction();
	if (func)
		BNShowGraphReport(GetView(func->GetView()), title.c_str(), graph->GetObject());
	else
		BNShowGraphReport(nullptr, title.c_str(), graph->GetObject());
}


void BinaryNinja::ShowReportCollection(const string& title, ReportCollection* reports)
{
	BNShowReportCollection(title.c_str(), reports->GetObject());
}


bool BinaryNinja::GetTextLineInput(string& result, const string& prompt, const string& title)
{
	char* value = nullptr;
	if (!BNGetTextLineInput(&value, prompt.c_str(), title.c_str()))
		return false;
	result = value;
	BNFreeString(value);
	return true;
}


bool BinaryNinja::GetIntegerInput(int64_t& result, const string& prompt, const string& title)
{
	return BNGetIntegerInput(&result, prompt.c_str(), title.c_str());
}


bool BinaryNinja::GetAddressInput(uint64_t& result, const string& prompt, const string& title)
{
	return BNGetAddressInput(&result, prompt.c_str(), title.c_str(), nullptr, 0);
}


bool BinaryNinja::GetChoiceInput(size_t& idx, const string& prompt, const string& title, const vector<string>& choices)
{
	const char** choiceStrs = new const char*[choices.size()];
	for (size_t i = 0; i < choices.size(); i++)
		choiceStrs[i] = choices[i].c_str();
	bool ok = BNGetChoiceInput(&idx, prompt.c_str(), title.c_str(), choiceStrs, choices.size());
	delete[] choiceStrs;
	return ok;
}


bool BinaryNinja::GetOpenFileNameInput(string& result, const string& prompt, const string& ext)
{
	char* value = nullptr;
	if (!BNGetOpenFileNameInput(&value, prompt.c_str(), ext.c_str()))
		return false;
	result = value;
	BNFreeString(value);
	return true;
}


bool BinaryNinja::GetSaveFileNameInput(
    string& result, const string& prompt, const string& ext, const string& defaultName)
{
	char* value = nullptr;
	if (!BNGetSaveFileNameInput(&value, prompt.c_str(), ext.c_str(), defaultName.c_str()))
		return false;
	result = value;
	BNFreeString(value);
	return true;
}


bool BinaryNinja::GetDirectoryNameInput(string& result, const string& prompt, const string& defaultName)
{
	char* value = nullptr;
	if (!BNGetDirectoryNameInput(&value, prompt.c_str(), defaultName.c_str()))
		return false;
	result = value;
	BNFreeString(value);
	return true;
}


bool BinaryNinja::GetFormInput(vector<FormInputField>& fields, const string& title)
{
	// Construct field list in core format
	BNFormInputField* fieldBuf = new BNFormInputField[fields.size()];
	for (size_t i = 0; i < fields.size(); i++)
	{
		fieldBuf[i].type = fields[i].type;
		fieldBuf[i].prompt = fields[i].prompt.c_str();
		switch (fields[i].type)
		{
		case AddressFormField:
			fieldBuf[i].view = fields[i].view ? GetView(fields[i].view) : nullptr;
			fieldBuf[i].currentAddress = fields[i].currentAddress;
			break;
		case ChoiceFormField:
			fieldBuf[i].choices = new const char*[fields[i].choices.size()];
			fieldBuf[i].count = fields[i].choices.size();
			for (size_t j = 0; j < fields[i].choices.size(); j++)
				fieldBuf[i].choices[j] = fields[i].choices[j].c_str();
			break;
		case OpenFileNameFormField:
			fieldBuf[i].ext = fields[i].ext.c_str();
			break;
		case SaveFileNameFormField:
			fieldBuf[i].ext = fields[i].ext.c_str();
			fieldBuf[i].defaultName = fields[i].defaultName.c_str();
			break;
		case DirectoryNameFormField:
			fieldBuf[i].defaultName = fields[i].defaultName.c_str();
			break;
		default:
			break;
		}
		fieldBuf[i].hasDefault = fields[i].hasDefault;
		if (fields[i].hasDefault)
		{
			switch (fields[i].type)
			{
			case TextLineFormField:
			case MultilineTextFormField:
			case OpenFileNameFormField:
			case SaveFileNameFormField:
			case DirectoryNameFormField:
				fieldBuf[i].stringDefault = fields[i].stringDefault.c_str();
				break;
			case IntegerFormField:
				fieldBuf[i].intDefault = fields[i].intDefault;
				break;
			case AddressFormField:
				fieldBuf[i].addressDefault = fields[i].addressDefault;
				break;
			case ChoiceFormField:
				fieldBuf[i].indexDefault = fields[i].indexDefault;
				break;
			default:
				break;
			}
		}
	}

	bool ok = BNGetFormInput(fieldBuf, fields.size(), title.c_str());

	// Free any memory used by field descriptions
	for (size_t i = 0; i < fields.size(); i++)
	{
		if (fields[i].type == ChoiceFormField)
			delete[] fieldBuf[i].choices;
	}

	// If user cancelled, there are no results
	if (!ok)
		return false;

	// Copy results to API structures
	for (size_t i = 0; i < fields.size(); i++)
	{
		switch (fields[i].type)
		{
		case TextLineFormField:
		case MultilineTextFormField:
		case OpenFileNameFormField:
		case SaveFileNameFormField:
		case DirectoryNameFormField:
			fields[i].stringResult = fieldBuf[i].stringResult;
			break;
		case IntegerFormField:
			fields[i].intResult = fieldBuf[i].intResult;
			break;
		case AddressFormField:
			fields[i].addressResult = fieldBuf[i].addressResult;
			break;
		case ChoiceFormField:
			fields[i].indexResult = fieldBuf[i].indexResult;
			break;
		default:
			break;
		}
	}

	BNFreeFormInputResults(fieldBuf, fields.size());
	return true;
}


BNMessageBoxButtonResult BinaryNinja::ShowMessageBox(
    const string& title, const string& text, BNMessageBoxButtonSet buttons, BNMessageBoxIcon icon)
{
	return BNShowMessageBox(title.c_str(), text.c_str(), buttons, icon);
}


bool BinaryNinja::OpenUrl(const std::string& url)
{
	return BNOpenUrl(url.c_str());
}


ReportCollection::ReportCollection()
{
	m_object = BNCreateReportCollection();
}


ReportCollection::ReportCollection(BNReportCollection* reports)
{
	m_object = reports;
}


size_t ReportCollection::GetCount() const
{
	return BNGetReportCollectionCount(m_object);
}


BNReportType ReportCollection::GetType(size_t i) const
{
	return BNGetReportType(m_object, i);
}


Ref<BinaryView> ReportCollection::GetView(size_t i) const
{
	BNBinaryView* view = BNGetReportView(m_object, i);
	if (!view)
		return nullptr;
	return CreateNewView(view);
}


string ReportCollection::GetTitle(size_t i) const
{
	char* str = BNGetReportTitle(m_object, i);
	string result = str;
	BNFreeString(str);
	return result;
}


string ReportCollection::GetContents(size_t i) const
{
	char* str = BNGetReportContents(m_object, i);
	string result = str;
	BNFreeString(str);
	return result;
}


string ReportCollection::GetPlainText(size_t i) const
{
	char* str = BNGetReportPlainText(m_object, i);
	string result = str;
	BNFreeString(str);
	return result;
}


Ref<FlowGraph> ReportCollection::GetFlowGraph(size_t i) const
{
	BNFlowGraph* graph = BNGetReportFlowGraph(m_object, i);
	if (!graph)
		return nullptr;
	return new CoreFlowGraph(graph);
}


void ReportCollection::AddPlainTextReport(Ref<BinaryView> view, const string& title, const string& contents)
{
	BNAddPlainTextReportToCollection(m_object, view ? BinaryNinja::GetView(view) : nullptr, title.c_str(), contents.c_str());
}


void ReportCollection::AddMarkdownReport(
    Ref<BinaryView> view, const string& title, const string& contents, const string& plainText)
{
	BNAddMarkdownReportToCollection(
	    m_object, view ? BinaryNinja::GetView(view) : nullptr, title.c_str(), contents.c_str(), plainText.c_str());
}


void ReportCollection::AddHTMLReport(
    Ref<BinaryView> view, const string& title, const string& contents, const string& plainText)
{
	BNAddHTMLReportToCollection(
	    m_object, view ? BinaryNinja::GetView(view) : nullptr, title.c_str(), contents.c_str(), plainText.c_str());
}


void ReportCollection::AddGraphReport(Ref<BinaryView> view, const string& title, Ref<FlowGraph> graph)
{
	BNAddGraphReportToCollection(m_object, view ? BinaryNinja::GetView(view) : nullptr, title.c_str(), graph->GetObject());
}


void ReportCollection::UpdateFlowGraph(size_t i, Ref<FlowGraph> graph)
{
	BNUpdateReportFlowGraph(m_object, i, graph->GetObject());
}
