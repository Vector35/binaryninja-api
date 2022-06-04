#include "languagerepresentation.hpp"
#include "architecture.hpp"
#include "function.hpp"

using namespace BinaryNinja;
using namespace std;

LanguageRepresentationFunction::LanguageRepresentationFunction(Architecture* arch, Function* func)
{
	m_object = BNCreateLanguageRepresentationFunction(arch->GetObject(), func ? func->GetObject() : nullptr);
}


LanguageRepresentationFunction::LanguageRepresentationFunction(BNLanguageRepresentationFunction* func)
{
	m_object = func;
}