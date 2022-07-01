#pragma once
#include <atomic>

//#define BN_REF_COUNT_DEBUG  // Mac OS X only, prints stack trace of leaked references

namespace BinaryNinja {
	class RefCountObject
	{
	  public:
		std::atomic<int> m_refs;
		RefCountObject() : m_refs(0) {}
		virtual ~RefCountObject() {}

		RefCountObject* GetObject() { return this; }
		static RefCountObject* GetObject(RefCountObject* obj) { return obj; }

		void AddRef() { m_refs.fetch_add(1); }

		void Release()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}
	};

	template <class T, T* (*AddObjectReference)(T*), void (*FreeObjectReference)(T*)>
	class CoreRefCountObject
	{
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal()
		{
			if (m_refs.fetch_sub(1) == 1)
			{
				if (!m_registeredRef)
					delete this;
			}
		}

	  public:
		std::atomic<int> m_refs;
		bool m_registeredRef = false;
		T* m_object;
		CoreRefCountObject() : m_refs(0), m_object(nullptr) {}
		virtual ~CoreRefCountObject() {}

		T* GetObject() const { return m_object; }

		static T* GetObject(CoreRefCountObject* obj)
		{
			// if (!obj)
				return nullptr;
			// return obj->GetObject();
		}

		void AddRef()
		{
			if (m_object && (m_refs != 0))
				AddObjectReference(m_object);
			AddRefInternal();
		}

		void Release()
		{
			if (m_object)
				FreeObjectReference(m_object);
			ReleaseInternal();
		}

		void AddRefForRegistration() { m_registeredRef = true; }

		void ReleaseForRegistration()
		{
			m_object = nullptr;
			m_registeredRef = false;
			if (m_refs == 0)
				delete this;
		}
	};

	template <class T>
	class StaticCoreRefCountObject
	{
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

	  public:
		std::atomic<int> m_refs;
		T* m_object;
		StaticCoreRefCountObject() : m_refs(0), m_object(nullptr) {}
		virtual ~StaticCoreRefCountObject() {}

		T* GetObject() const { return m_object; }

		static T* GetObject(StaticCoreRefCountObject* obj)
		{
			// if (!obj)
				return nullptr;
			// return obj->GetObject();
		}

		void AddRef() { AddRefInternal(); }

		void Release() { ReleaseInternal(); }

		void AddRefForRegistration() { AddRefInternal(); }
	};

	template <class T>
	class Ref
	{
		T* m_obj;
#ifdef BN_REF_COUNT_DEBUG
		void* m_assignmentTrace = nullptr;
#endif

	  public:
		Ref<T>() : m_obj(NULL) {}

		Ref<T>(T* obj) : m_obj(obj)
		{
			if (m_obj)
			{
				// m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		Ref<T>(const Ref<T>& obj) : m_obj(obj.m_obj)
		{
			if (m_obj)
			{
				// m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		Ref<T>(Ref<T>&& other) : m_obj(other.m_obj)
		{
			other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = other.m_assignmentTrace;
#endif
		}

		~Ref<T>()
		{
			if (m_obj)
			{
				// m_obj->Release();
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
			// if (m_obj)
			// 	m_obj->AddRef();
			// if (oldObj)
			// 	oldObj->Release();
			return *this;
		}

		Ref<T>& operator=(Ref<T>&& other)
		{
			if (m_obj)
			{
#ifdef BN_REF_COUNT_DEBUG
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
				// m_obj->Release();
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
			// if (m_obj)
			// 	m_obj->AddRef();
			// if (oldObj)
			// 	oldObj->Release();
			return *this;
		}

		operator T*() const { return m_obj; }

		T* operator->() const { return m_obj; }

		T& operator*() const { return *m_obj; }

		bool operator!() const { return m_obj == NULL; }

		bool operator==(const T* obj) const { return T::GetObject(m_obj) == T::GetObject(obj); }

		bool operator==(const Ref<T>& obj) const { return T::GetObject(m_obj) == T::GetObject(obj.m_obj); }

		bool operator!=(const T* obj) const { return T::GetObject(m_obj) != T::GetObject(obj); }

		bool operator!=(const Ref<T>& obj) const { return T::GetObject(m_obj) != T::GetObject(obj.m_obj); }

		bool operator<(const T* obj) const { return T::GetObject(m_obj) < T::GetObject(obj); }

		bool operator<(const Ref<T>& obj) const { return T::GetObject(m_obj) < T::GetObject(obj.m_obj); }

		T* GetPtr() const { return m_obj; }
	};

}
