

#include "binaryninja/binaryninjaapi_new.hpp"
#include "binaryninjacore/binaryninjacore.h"
using namespace std;

string BinaryNinja::GetUniqueIdentifierString()
{
	char* str = BNGetUniqueIdentifierString();
	string result = str;
	BNFreeString(str);
	return result;
}
