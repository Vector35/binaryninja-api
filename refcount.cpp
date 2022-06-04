#include "refcount.hpp"

using namespace BinaryNinja;
using namespace std;

void CoreRefCountObject::AddRefInternal()
{
	m_refs.fetch_add(1);
}

void CoreRefCountObject::ReleaseInternal()
{
	if (m_refs.fetch_sub(1) == 1)
	{
		if (!m_registeredRef)
			delete this;
	}
}

CoreRefCountObject::CoreRefCountObject()
	: m_refs(0), m_object(nullptr)
{}

CoreRefCountObject::~CoreRefCountObject()
{}


T* CoreRefCountObject::GetObject() const { return m_object; }

static T* CoreRefCountObject::GetObject(CoreRefCountObject* obj)
{
	if (!obj)
		return nullptr;
	return obj->GetObject();
}

void CoreRefCountObject::AddRef()
{
	if (m_object && (m_refs != 0))
		AddObjectReference(m_object);
	AddRefInternal();
}

void CoreRefCountObject::Release()
{
	if (m_object)
		FreeObjectReference(m_object);
	ReleaseInternal();
}

void CoreRefCountObject::AddRefForRegistration()
{
	m_registeredRef = true;
}

void CoreRefCountObject::ReleaseForRegistration()
{
	m_object = nullptr;
	m_registeredRef = false;
	if (m_refs == 0)
		delete this;
}


void StaticCoreRefCountObject::AddRefInternal() { m_refs.fetch_add(1); }

void StaticCoreRefCountObject::ReleaseInternal()
{
	if (m_refs.fetch_sub(1) == 1)
		delete this;
}

SStaticCoreRefCountObject::taticCoreRefCountObject() : m_refs(0), m_object(nullptr) {}
virtual StaticCoreRefCountObject::~StaticCoreRefCountObject() {}

T* GetObject() const { return m_object; }

static T* StaticCoreRefCountObject::GetObject(StaticCoreRefCountObject* obj)
{
	if (!obj)
		return nullptr;
	return obj->GetObject();
}

void StaticCoreRefCountObject::AddRef() { AddRefInternal(); }

void StaticCoreRefCountObject::Release() { ReleaseInternal(); }

void StaticCoreRefCountObject::AddRefForRegistration() { AddRefInternal(); }




Ref<T>::Ref<T>() : m_obj(NULL) {}

Ref<T>::Ref<T>(T* obj) : m_obj(obj)
{
	if (m_obj)
	{
		m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
		m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
	}
}

Ref<T>::Ref<T>(const Ref<T>& obj) : m_obj(obj.m_obj)
{
	if (m_obj)
	{
		m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
		m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
	}
}

Ref<T>::Ref<T>(Ref<T>&& other) : m_obj(other.m_obj)
{
	other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
	m_assignmentTrace = other.m_assignmentTrace;
#endif
}

Ref<T>::~Ref<T>()
{
	if (m_obj)
	{
		m_obj->Release();
#ifdef BN_REF_COUNT_DEBUG
		BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
	}
}

Ref<T>& operator=(const Ref<T>& obj)
{
#ifdef BN_REF_COUNT_DEBUG
	if (m_obj)
		BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
	if (obj.m_obj)
		m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
	T* oldObj = m_obj;
	m_obj = obj.m_obj;
	if (m_obj)
		m_obj->AddRef();
	if (oldObj)
		oldObj->Release();
	return *this;
}

Ref<T>& operator=(Ref<T>&& other)
{
	if (m_obj)
	{
#ifdef BN_REF_COUNT_DEBUG
		BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
		m_obj->Release();
	}
	m_obj = other.m_obj;
	other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
	m_assignmentTrace = other.m_assignmentTrace;
#endif
	return *this;
}

Ref<T>& operator=(T* obj)
{
#ifdef BN_REF_COUNT_DEBUG
	if (m_obj)
		BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
	if (obj)
		m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
	T* oldObj = m_obj;
	m_obj = obj;
	if (m_obj)
		m_obj->AddRef();
	if (oldObj)
		oldObj->Release();
	return *this;
}

operator Ref::T*() const { return m_obj; }

T* Ref::operator->() const { return m_obj; }

T& Ref::operator*() const { return *m_obj; }

bool Ref::operator!() const { return m_obj == NULL; }

bool Ref::operator==(const T* obj) const { return T::GetObject(m_obj) == T::GetObject(obj); }

bool Ref::operator==(const Ref<T>& obj) const { return T::GetObject(m_obj) == T::GetObject(obj.m_obj); }

bool Ref::operator!=(const T* obj) const { return T::GetObject(m_obj) != T::GetObject(obj); }

bool Ref::operator!=(const Ref<T>& obj) const { return T::GetObject(m_obj) != T::GetObject(obj.m_obj); }

bool Ref::operator<(const T* obj) const { return T::GetObject(m_obj) < T::GetObject(obj); }

bool Ref::operator<(const Ref<T>& obj) const { return T::GetObject(m_obj) < T::GetObject(obj.m_obj); }

T* Ref::GetPtr() const { return m_obj; }
