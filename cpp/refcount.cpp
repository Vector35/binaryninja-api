//#include "binaryninja/refcount.hpp"
//
//using namespace BinaryNinja;
//using namespace std;
//
//// void CoreRefCountObject::AddRefInternal()
//// {
//// 	m_refs.fetch_add(1);
//// }
//
//// void CoreRefCountObject::ReleaseInternal()
//// {
//// 	if (m_refs.fetch_sub(1) == 1)
//// 	{
//// 		if (!m_registeredRef)
//// 			delete this;
//// 	}
//// }
//
//// CoreRefCountObject::CoreRefCountObject()
//// 	: m_refs(0), m_object(nullptr)
//// {}
//
//// CoreRefCountObject::~CoreRefCountObject()
//// {}
//
//
//// T* CoreRefCountObject::GetObject() const
//// {
//// 	return m_object;
//// }
//
//// static T* CoreRefCountObject::GetObject(CoreRefCountObject* obj)
//// {
//// 	if (!obj)
//// 		return nullptr;
//// 	return obj->GetObject();
//// }
//
//// void CoreRefCountObject::AddRef()
//// {
//// 	if (m_object && (m_refs != 0))
//// 		AddObjectReference(m_object);
//// 	AddRefInternal();
//// }
//
//// void CoreRefCountObject::Release()
//// {
//// 	if (m_object)
//// 		FreeObjectReference(m_object);
//// 	ReleaseInternal();
//// }
//
//// void CoreRefCountObject::AddRefForRegistration()
//// {
//// 	m_registeredRef = true;
//// }
//
//// void CoreRefCountObject::ReleaseForRegistration()
//// {
//// 	m_object = nullptr;
//// 	m_registeredRef = false;
//// 	if (m_refs == 0)
//// 		delete this;
//// }
//
//template <class T>
//void StaticCoreRefCountObject<T>::AddRefInternal()
//{
//	m_refs.fetch_add(1);
//}
//
//template <class T>
//void StaticCoreRefCountObject<T>::ReleaseInternal()
//{
//	if (m_refs.fetch_sub(1) == 1)
//		delete this;
//}
//
//template <class T>
//StaticCoreRefCountObject<T>::StaticCoreRefCountObject()
//	: m_refs(0), m_object(nullptr)
//{}
//
//
//template <class T>
//T* StaticCoreRefCountObject<T>::GetObject() const { return m_object; }
//
//
//template <class T>
//T* StaticCoreRefCountObject<T>::GetObject(StaticCoreRefCountObject* obj)
//{
//	if (!obj)
//		return nullptr;
//	return obj->GetObject();
//}
//
//
//template <class T>
//void StaticCoreRefCountObject<T>::AddRef() { AddRefInternal(); }
//
//
//template <class T>
//void StaticCoreRefCountObject<T>::Release() { ReleaseInternal(); }
//
//
//template <class T>
//void StaticCoreRefCountObject<T>::AddRefForRegistration() { AddRefInternal(); }
//
//
//
//template <class T>
//Ref<T>::Ref() : m_obj(NULL) {}
//
//template <class T>
//Ref<T>::Ref(T* obj) : m_obj(obj)
//{
//	if (m_obj)
//	{
//		m_obj->AddRef();
//#ifdef BN_REF_COUNT_DEBUG
//		m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
//#endif
//	}
//}
//
//template <class T>
//Ref<T>::Ref(const Ref<T>& obj) : m_obj(obj.m_obj)
//{
//	if (m_obj)
//	{
//		m_obj->AddRef();
//#ifdef BN_REF_COUNT_DEBUG
//		m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
//#endif
//	}
//}
//
//template <class T>
//Ref<T>::Ref(Ref<T>&& other) : m_obj(other.m_obj)
//{
//	other.m_obj = 0;
//#ifdef BN_REF_COUNT_DEBUG
//	m_assignmentTrace = other.m_assignmentTrace;
//#endif
//}
//
//template <class T>
//Ref<T>::~Ref()
//{
//	if (m_obj)
//	{
//		m_obj->Release();
//#ifdef BN_REF_COUNT_DEBUG
//		BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
//#endif
//	}
//}
//
//template <class T>
//Ref<T>& Ref<T>::operator=(const Ref<T>& obj)
//{
//#ifdef BN_REF_COUNT_DEBUG
//	if (m_obj)
//		BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
//	if (obj.m_obj)
//		m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
//#endif
//	T* oldObj = m_obj;
//	m_obj = obj.m_obj;
//	if (m_obj)
//		m_obj->AddRef();
//	if (oldObj)
//		oldObj->Release();
//	return *this;
//}
//
//template <class T>
//Ref<T>& Ref<T>::operator=(Ref<T>&& other)
//{
//	if (m_obj)
//	{
//#ifdef BN_REF_COUNT_DEBUG
//		BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
//#endif
//		m_obj->Release();
//	}
//	m_obj = other.m_obj;
//	other.m_obj = 0;
//#ifdef BN_REF_COUNT_DEBUG
//	m_assignmentTrace = other.m_assignmentTrace;
//#endif
//	return *this;
//}
//
//template <class T>
//Ref<T>& Ref<T>::operator=(T* obj)
//{
//#ifdef BN_REF_COUNT_DEBUG
//	if (m_obj)
//		BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
//	if (obj)
//		m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
//#endif
//	T* oldObj = m_obj;
//	m_obj = obj;
//	if (m_obj)
//		m_obj->AddRef();
//	if (oldObj)
//		oldObj->Release();
//	return *this;
//}
//
//// template <typename T> operator Ref<T>::T*() const
//
//
//template <class T>
//T* Ref<T>::operator->() const { return m_obj; }
//
//template <class T>
//T& Ref<T>::operator*() const { return *m_obj; }
//
//template <class T>
//bool Ref<T>::operator!() const { return m_obj == NULL; }
//
//template <class T>
//bool Ref<T>::operator==(const T* obj) const { return T::GetObject(m_obj) == T::GetObject(obj); }
//
//template <class T>
//bool Ref<T>::operator==(const Ref<T>& obj) const { return T::GetObject(m_obj) == T::GetObject(obj.m_obj); }
//
//template <class T>
//bool Ref<T>::operator!=(const T* obj) const { return T::GetObject(m_obj) != T::GetObject(obj); }
//
//template <class T>
//bool Ref<T>::operator!=(const Ref<T>& obj) const { return T::GetObject(m_obj) != T::GetObject(obj.m_obj); }
//
//template <class T>
//bool Ref<T>::operator<(const T* obj) const { return T::GetObject(m_obj) < T::GetObject(obj); }
//
//template <class T>
//bool Ref<T>::operator<(const Ref<T>& obj) const { return T::GetObject(m_obj) < T::GetObject(obj.m_obj); }
//
//template <class T>
//T* Ref<T>::GetPtr() const { return m_obj; }
