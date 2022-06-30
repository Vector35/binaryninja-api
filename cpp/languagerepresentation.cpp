#include "binaryninja/languagerepresentation.hpp"
#include "binaryninja/getobject.hpp"

using namespace BinaryNinja;
using namespace std;

LanguageRepresentationFunction::LanguageRepresentationFunction(Architecture* arch, Function* func)
{
	m_object = BNCreateLanguageRepresentationFunction(BinaryNinja::GetObject(arch), BinaryNinja::GetObject(func));
}


LanguageRepresentationFunction::LanguageRepresentationFunction(BNLanguageRepresentationFunction* func)
{
	m_object = func;
}