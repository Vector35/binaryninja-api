#include "namelist.h"

using namespace BinaryNinja;
using namespace std;


NameList::NameList(const string& join, size_t size) : m_join(join)
{
	m_name.reserve(size);
}


NameList::NameList(const BNQualifiedName* name)
{
	if (name->join)
		m_join = name->join;
	m_name.reserve(name->nameCount);
	for (size_t i = 0; i < name->nameCount; i++)
		m_name.push_back(name->name[i]);
}


NameList::NameList(const string& name, const string& join) : m_join(join)
{
	if (!name.empty())
		m_name.push_back(name);
}


NameList::NameList(const vector<string>& name, const string& join) : m_join(join), m_name(name) {}


NameList::NameList(const NameList& name, const string& join) : m_join(join), m_name(name.m_name) {}

NameList::NameList(const NameList& name) : m_join(name.m_join), m_name(name.m_name) {}

NameList::~NameList() {}

NameList& NameList::operator=(const string& name)
{
	m_name = vector<string> {name};
	return *this;
}


NameList& NameList::operator=(const vector<string>& name)
{
	m_name = name;
	return *this;
}


NameList& NameList::operator=(const NameList& name)
{
	m_name = name.m_name;
	m_join = name.m_join;
	return *this;
}


bool NameList::operator==(const NameList& other) const
{
	return m_name == other.m_name && m_join == other.m_join;
}


bool NameList::operator!=(const NameList& other) const
{
	return m_name != other.m_name || m_join != other.m_join;
}


bool NameList::operator<(const NameList& other) const
{
	if (m_name < other.m_name)
		return true;
	if (m_name > other.m_name)
		return false;
	return m_join < other.m_join;
}


bool NameList::operator>(const NameList& other) const
{
	if (m_name > other.m_name)
		return true;
	if (m_name < other.m_name)
		return false;
	return m_join > other.m_join;
}


NameList NameList::operator+(const NameList& other) const
{
	NameList result(*this);
	result.m_name.insert(result.m_name.end(), other.m_name.begin(), other.m_name.end());
	return result;
}


string& NameList::operator[](size_t i)
{
	return m_name[i];
}


const string& NameList::operator[](size_t i) const
{
	return m_name[i];
}


vector<string>::iterator NameList::begin()
{
	return m_name.begin();
}


vector<string>::iterator NameList::end()
{
	return m_name.end();
}


vector<string>::const_iterator NameList::begin() const
{
	return m_name.begin();
}


vector<string>::const_iterator NameList::end() const
{
	return m_name.end();
}


string& NameList::front()
{
	return m_name.front();
}


const string& NameList::front() const
{
	return m_name.front();
}


string& NameList::back()
{
	return m_name.back();
}


const string& NameList::back() const
{
	return m_name.back();
}


void NameList::insert(vector<string>::iterator loc, const string& name)
{
	m_name.insert(loc, name);
}


void NameList::insert(vector<string>::iterator loc, vector<string>::iterator b, vector<string>::iterator e)
{
	m_name.insert(loc, b, e);
}


void NameList::erase(vector<string>::iterator i)
{
	m_name.erase(i);
}


void NameList::clear()
{
	m_name.clear();
}


void NameList::push_back(const string& name)
{
	m_name.push_back(name);
}


size_t NameList::size() const
{
	return m_name.size();
}


size_t NameList::StringSize() const
{
	if (m_name.size() == 0)
		return 0;
	size_t size = 0;
	for (auto& name : m_name)
		size += name.size() + m_join.size();
	return size - m_join.size();
}


string NameList::GetString(BNTokenEscapingType escaping) const
{
	bool first = true;
	string out;
	for (auto& name : m_name)
	{
		if (!first)
		{
			out += m_join + name;
		}
		else
		{
			out += name;
		}
		if (name.length() != 0)
			first = false;
	}
	return EscapeTypeName(out, escaping);
}


std::string NameList::EscapeTypeName(const std::string& name, BNTokenEscapingType escaping)
{
	char* str = BNEscapeTypeName(name.c_str(), escaping);
	std::string result(str);
	BNFreeString(str);
	return result;
}


std::string NameList::UnescapeTypeName(const std::string& name, BNTokenEscapingType escaping)
{
	char* str = BNUnescapeTypeName(name.c_str(), escaping);
	std::string result(str);
	BNFreeString(str);
	return result;
}


BNNameList NameList::GetAPIObject() const
{
	BNNameList result;
	result.nameCount = m_name.size();
	result.join = BNAllocString(m_join.c_str());
	result.name = new char*[m_name.size()];
	for (size_t i = 0; i < m_name.size(); i++)
		result.name[i] = BNAllocString(m_name[i].c_str());
	return result;
}


void NameList::FreeAPIObject(BNNameList* name)
{
	for (size_t i = 0; i < name->nameCount; i++)
		BNFreeString(name->name[i]);
	BNFreeString(name->join);
	delete[] name->name;
}


NameList NameList::FromAPIObject(BNNameList* name)
{
	NameList result(name->join);
	for (size_t i = 0; i < name->nameCount; i++)
		result.push_back(name->name[i]);
	return result;
}


QualifiedName::QualifiedName() : NameList("::") {}


QualifiedName::QualifiedName(const BNQualifiedName* name) : NameList(name) {}


QualifiedName::QualifiedName(const string& name) : NameList(name, "::") {}


QualifiedName::QualifiedName(const vector<string>& name) : NameList(name, "::") {}


QualifiedName::QualifiedName(const QualifiedName& name) : NameList(name.m_name, "::") {}


QualifiedName::~QualifiedName() {}


QualifiedName& QualifiedName::operator=(const string& name)
{
	m_name = vector<string> {name};
	m_join = "::";
	return *this;
}


QualifiedName& QualifiedName::operator=(const vector<string>& name)
{
	m_name = name;
	m_join = "::";
	return *this;
}


QualifiedName& QualifiedName::operator=(const QualifiedName& name)
{
	m_name = name.m_name;
	m_join = "::";
	return *this;
}


QualifiedName QualifiedName::operator+(const QualifiedName& other) const
{
	QualifiedName result(*this);
	result.m_join = "::";
	result.m_name.insert(result.m_name.end(), other.m_name.begin(), other.m_name.end());
	return result;
}


BNQualifiedName QualifiedName::GetAPIObject() const
{
	BNQualifiedName result;
	result.nameCount = m_name.size();
	result.join = BNAllocString(m_join.c_str());
	result.name = new char*[m_name.size()];
	for (size_t i = 0; i < m_name.size(); i++)
		result.name[i] = BNAllocString(m_name[i].c_str());
	return result;
}


void QualifiedName::FreeAPIObject(BNQualifiedName* name)
{
	for (size_t i = 0; i < name->nameCount; i++)
		BNFreeString(name->name[i]);
	BNFreeString(name->join);
	delete[] name->name;
}


QualifiedName QualifiedName::FromAPIObject(const BNQualifiedName* name)
{
	return QualifiedName(name);
}


NameSpace::NameSpace() : NameList("::") {}


NameSpace::NameSpace(const string& name) : NameList(name, "::") {}


NameSpace::NameSpace(const vector<string>& name) : NameList(name, "::") {}


NameSpace::NameSpace(const NameSpace& name) : NameList(name.m_name, "::") {}


NameSpace::~NameSpace() {}


NameSpace& NameSpace::operator=(const string& name)
{
	m_name = vector<string> {name};
	m_join = "::";
	return *this;
}


NameSpace& NameSpace::operator=(const vector<string>& name)
{
	m_name = name;
	m_join = "::";
	return *this;
}


NameSpace& NameSpace::operator=(const NameSpace& name)
{
	m_name = name.m_name;
	m_join = "::";
	return *this;
}


NameSpace NameSpace::operator+(const NameSpace& other) const
{
	NameSpace result(*this);
	result.m_join = "::";
	result.m_name.insert(result.m_name.end(), other.m_name.begin(), other.m_name.end());
	return result;
}


bool NameSpace::IsDefaultNameSpace() const
{
	return ((GetString() == DEFAULT_INTERNAL_NAMESPACE) || (GetString() == DEFAULT_EXTERNAL_NAMESPACE));
}


BNNameSpace NameSpace::GetAPIObject() const
{
	BNNameSpace result;
	result.nameCount = m_name.size();
	result.join = BNAllocString(m_join.c_str());
	result.name = new char*[m_name.size()];
	for (size_t i = 0; i < m_name.size(); i++)
		result.name[i] = BNAllocString(m_name[i].c_str());
	return result;
}


void NameSpace::FreeAPIObject(BNNameSpace* name)
{
	if (!name)
		return;
	for (size_t i = 0; i < name->nameCount; i++)
		BNFreeString(name->name[i]);
	BNFreeString(name->join);
	delete[] name->name;
}


NameSpace NameSpace::FromAPIObject(const BNNameSpace* name)
{
	NameSpace result;
	if (!name)
		return result;
	for (size_t i = 0; i < name->nameCount; i++)
		result.push_back(name->name[i]);
	return result;
}
