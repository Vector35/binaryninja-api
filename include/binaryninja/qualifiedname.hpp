#pragma once
#include <string>
#include <vector>
#include "binaryninjacore/qualifiedname.h"
#include "binaryninjacore/type.h"

namespace BinaryNinja {

	class Type;
	class NameList
	{
	  protected:
		std::string m_join;
		std::vector<std::string> m_name;

	  public:
		NameList(const std::string& join);
		NameList(const std::string& name, const std::string& join);
		NameList(const std::vector<std::string>& name, const std::string& join);
		NameList(const NameList& name, const std::string& join);
		NameList(const NameList& name);
		virtual ~NameList();

		virtual NameList& operator=(const std::string& name);
		virtual NameList& operator=(const std::vector<std::string>& name);
		virtual NameList& operator=(const NameList& name);

		virtual bool operator==(const NameList& other) const;
		virtual bool operator!=(const NameList& other) const;
		virtual bool operator<(const NameList& other) const;
		virtual bool operator>(const NameList& other) const;

		virtual NameList operator+(const NameList& other) const;

		virtual std::string& operator[](size_t i);
		virtual const std::string& operator[](size_t i) const;
		virtual std::vector<std::string>::iterator begin();
		virtual std::vector<std::string>::iterator end();
		virtual std::vector<std::string>::const_iterator begin() const;
		virtual std::vector<std::string>::const_iterator end() const;
		virtual std::string& front();
		virtual const std::string& front() const;
		virtual std::string& back();
		virtual const std::string& back() const;
		virtual void insert(std::vector<std::string>::iterator loc, const std::string& name);
		virtual void insert(std::vector<std::string>::iterator loc, std::vector<std::string>::iterator b,
		    std::vector<std::string>::iterator e);
		virtual void erase(std::vector<std::string>::iterator i);
		virtual void clear();
		virtual void push_back(const std::string& name);
		virtual size_t size() const;
		virtual size_t StringSize() const;

		virtual std::string GetString(BNTokenEscapingType escaping = NoTokenEscapingType) const;
		virtual std::string GetJoinString() const { return m_join; }
		virtual bool IsEmpty() const { return m_name.size() == 0; }

		static std::string EscapeTypeName(const std::string& name, BNTokenEscapingType escaping);
		static std::string UnescapeTypeName(const std::string& name, BNTokenEscapingType escaping);

		BNNameList GetAPIObject() const;
		static void FreeAPIObject(BNNameList* name);
		static NameList FromAPIObject(BNNameList* name);
	};

	class QualifiedName : public NameList
	{
	  public:
		QualifiedName();
		QualifiedName(const std::string& name);
		QualifiedName(const std::vector<std::string>& name);
		QualifiedName(const QualifiedName& name);
		virtual ~QualifiedName();

		virtual QualifiedName& operator=(const std::string& name);
		virtual QualifiedName& operator=(const std::vector<std::string>& name);
		virtual QualifiedName& operator=(const QualifiedName& name);
		virtual QualifiedName operator+(const QualifiedName& other) const;

		BNQualifiedName GetAPIObject() const;
		static void FreeAPIObject(BNQualifiedName* name);
		static QualifiedName FromAPIObject(const BNQualifiedName* name);
	};

	struct QualifiedNameAndType
	{
		QualifiedName name;
		Ref<Type> type;

		QualifiedNameAndType() = default;
		QualifiedNameAndType(const std::string& name, const Ref<Type>& type);
		QualifiedNameAndType(const QualifiedName& name, const Ref<Type>& type);
		bool operator<(const QualifiedNameAndType& other) const;
	};

	class NameSpace : public NameList
	{
	  public:
		NameSpace();
		NameSpace(const std::string& name);
		NameSpace(const std::vector<std::string>& name);
		NameSpace(const NameSpace& name);
		virtual ~NameSpace();

		virtual NameSpace& operator=(const std::string& name);
		virtual NameSpace& operator=(const std::vector<std::string>& name);
		virtual NameSpace& operator=(const NameSpace& name);
		virtual NameSpace operator+(const NameSpace& other) const;

		virtual bool IsDefaultNameSpace() const;
		BNNameSpace GetAPIObject() const;
		static void FreeAPIObject(BNNameSpace* name);
		static NameSpace FromAPIObject(const BNNameSpace* name);
	};
};