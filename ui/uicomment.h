#pragma once

#include "binaryninjaapi.h"
#include "uicontext.h"

// these are only intended to be used for the ui
typedef enum
{
	FunctionComment,
	AddressComment,
	DataComment
} UICommentType;

class UIComment
{
  public:
	UICommentType type;
	FunctionRef func;
	BinaryViewRef data;
	uint64_t address;
	QString content;


	UIComment(UICommentType type, FunctionRef func, uint64_t address, QString content) :
	    type(type), func(func), address(address), content(content)
	{}


	UIComment(UICommentType type, BinaryViewRef data, uint64_t address, QString content) :
	    type(type), data(data), address(address), content(content)
	{}


	UIComment(const UIComment& rhs)
	{
		type = rhs.type;
		func = rhs.func;
		data = rhs.data;
		address = rhs.address;
		content = rhs.content;
	}
};