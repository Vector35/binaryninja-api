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
		void AddRefInternal();
		void ReleaseInternal();

	  public:
		std::atomic<int> m_refs;
		bool m_registeredRef = false;
		T* m_object;
		CoreRefCountObject();
		virtual ~CoreRefCountObject() = default;

		void AddRef();
		void Release();
		void AddRefForRegistration();
		void ReleaseForRegistration();
		T* GetObject() const;
		static T* GetObject(CoreRefCountObject* obj);
	};

	template <class T>
	class StaticCoreRefCountObject
	{
		void AddRefInternal();
		void ReleaseInternal();

	  public:
		std::atomic<int> m_refs;
		T* m_object;

		StaticCoreRefCountObject();
		virtual ~StaticCoreRefCountObject() = default;
		T* GetObject() const;
		static T* GetObject(StaticCoreRefCountObject* obj);

		void AddRef();
		void Release();
		void AddRefForRegistration();
	};

	template <class T>
	class Ref
	{
		T* m_obj;
#ifdef BN_REF_COUNT_DEBUG
		void* m_assignmentTrace = nullptr;
#endif

	  public:
		Ref<T>();
		Ref<T>(T* obj);
		Ref<T>(const Ref<T>& obj);
		Ref<T>(Ref<T>&& other);
		~Ref<T>();
		Ref<T>& operator=(const Ref<T>& obj);
		Ref<T>& operator=(Ref<T>&& other);
		Ref<T>& operator=(T* obj);
		operator T*() const { return m_obj;}
		T* operator->() const;
		T& operator*() const;
		bool operator!() const;
		bool operator==(const T* obj) const;
		bool operator==(const Ref<T>& obj) const;
		bool operator!=(const T* obj) const;
		bool operator!=(const Ref<T>& obj) const;
		bool operator<(const T* obj) const;
		bool operator<(const Ref<T>& obj) const;
		T* GetPtr() const;
	};
}