


using namespace BinaryNinja;
using namespace std;

#include "binaryninjaapi_new.h"

string BinaryNinja::GetUniqueIdentifierString()
{
	char* str = BNGetUniqueIdentifierString();
	string result = str;
	BNFreeString(str);
	return result;
}
