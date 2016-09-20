#include <stdlib.h>
#include <string.h>
#include "binaryninjaapi.h"

using namespace std;
using namespace BinaryNinja;


void InteractionHandler::ShowMarkdownReport(Ref<BinaryView> view, const string& title, const string& contents,
	const string& plainText)
{
	ShowHTMLReport(view, title, MarkdownToHTML(contents), plainText);
}


void InteractionHandler::ShowHTMLReport(Ref<BinaryView> view, const string& title, const string&,
	const string& plainText)
{
	if (plainText.size() != 0)
		ShowPlainTextReport(view, title, plainText);
}


bool InteractionHandler::GetIntegerInput(int64_t& result, const string& prompt, const string& title)
{
	string input;

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


bool InteractionHandler::GetAddressInput(uint64_t& result, const string& prompt, const string& title,
	Ref<BinaryView>, uint64_t)
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
	handler->ShowPlainTextReport(view ? new BinaryView(BNNewViewReference(view)) : nullptr, title, contents);
}


static void ShowMarkdownReportCallback(void* ctxt, BNBinaryView* view, const char* title, const char* contents,
	const char* plaintext)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	handler->ShowMarkdownReport(view ? new BinaryView(BNNewViewReference(view)) : nullptr, title, contents, plaintext);
}


static void ShowHTMLReportCallback(void* ctxt, BNBinaryView* view, const char* title, const char* contents,
	const char* plaintext)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	handler->ShowHTMLReport(view ? new BinaryView(BNNewViewReference(view)) : nullptr, title, contents, plaintext);
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


static bool GetAddressInputCallback(void* ctxt, uint64_t* result, const char* prompt, const char* title,
	BNBinaryView* view, uint64_t currentAddr)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	return handler->GetAddressInput(*result, prompt, title, view ? new BinaryView(BNNewViewReference(view)) : nullptr,
		currentAddr);
}


static bool GetChoiceInputCallback(void* ctxt, size_t* result, const char* prompt, const char* title,
	const char** choices, size_t count)
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


static bool GetSaveFileNameInputCallback(void* ctxt, char** result, const char* prompt, const char* ext,
	const char* defaultName)
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


static BNMessageBoxButtonResult ShowMessageBoxCallback(void* ctxt, const char* title, const char* text,
	BNMessageBoxButtonSet buttons, BNMessageBoxIcon icon)
{
	InteractionHandler* handler = (InteractionHandler*)ctxt;
	return handler->ShowMessageBox(title, text, buttons, icon);
}


void BinaryNinja::RegisterInteractionHandler(InteractionHandler* handler)
{
	BNInteractionHandlerCallbacks cb;
	cb.context = handler;
	cb.showPlainTextReport = ShowPlainTextReportCallback;
	cb.showMarkdownReport = ShowMarkdownReportCallback;
	cb.showHTMLReport = ShowHTMLReportCallback;
	cb.getTextLineInput = GetTextLineInputCallback;
	cb.getIntegerInput = GetIntegerInputCallback;
	cb.getAddressInput = GetAddressInputCallback;
	cb.getChoiceInput = GetChoiceInputCallback;
	cb.getOpenFileNameInput = GetOpenFileNameInputCallback;
	cb.getSaveFileNameInput = GetSaveFileNameInputCallback;
	cb.getDirectoryNameInput = GetDirectoryNameInputCallback;
	cb.showMessageBox = ShowMessageBoxCallback;
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


bool BinaryNinja::GetChoiceInput(size_t& idx, const string& prompt, const string& title,
	const vector<string>& choices)
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


bool BinaryNinja::GetSaveFileNameInput(string& result, const string& prompt, const string& ext,
	const string& defaultName)
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


BNMessageBoxButtonResult BinaryNinja::ShowMessageBox(const string& title, const string& text,
	BNMessageBoxButtonSet buttons, BNMessageBoxIcon icon)
{
	return BNShowMessageBox(title.c_str(), text.c_str(), buttons, icon);
}
