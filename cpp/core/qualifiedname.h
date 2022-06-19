#pragma once

extern "C" {
	struct BNNameList
	{
		char** name;
		char* join;
		size_t nameCount;
	};

	struct BNNameSpace
	{
		char** name;
		char* join;
		size_t nameCount;
	};

	struct BNQualifiedName
	{
		char** name;
		char* join;
		size_t nameCount;
	};
}