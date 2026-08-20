#pragma once

#include <binaryninjaapi.h>
#include "kernelcachecore.h"

template<class T>
class KCRefCountObject {
	void AddRefInternal() { m_refs.fetch_add(1); }

	void ReleaseInternal() {
		if (m_refs.fetch_sub(1) == 1)
			delete this;
	}

public:
	std::atomic<int> m_refs;
	T *m_object;

	KCRefCountObject() : m_refs(0), m_object(nullptr) {}

	virtual ~KCRefCountObject() = default;

	T *GetObject() const { return m_object; }

	static T *GetObject(KCRefCountObject *obj) {
		if (!obj)
			return nullptr;
		return obj->GetObject();
	}

	void AddRef() { AddRefInternal(); }

	void Release() { ReleaseInternal(); }

	void AddRefForRegistration() { AddRefInternal(); }
};


template<class T, T *(*AddObjectReference)(T *), void (*FreeObjectReference)(T *)>
class KCCoreRefCountObject {
	void AddRefInternal() { m_refs.fetch_add(1); }

	void ReleaseInternal() {
		if (m_refs.fetch_sub(1) == 1) {
			if (!m_registeredRef)
				delete this;
		}
	}

public:
	std::atomic<int> m_refs;
	bool m_registeredRef = false;
	T *m_object;

	KCCoreRefCountObject() : m_refs(0), m_object(nullptr) {}

	virtual ~KCCoreRefCountObject() = default;

	T *GetObject() const { return m_object; }

	static T *GetObject(KCCoreRefCountObject *obj) {
		if (!obj)
			return nullptr;
		return obj->GetObject();
	}

	void AddRef() {
		if (m_object && (m_refs != 0))
			AddObjectReference(m_object);
		AddRefInternal();
	}

	void Release() {
		if (m_object)
			FreeObjectReference(m_object);
		ReleaseInternal();
	}

	void AddRefForRegistration() { m_registeredRef = true; }

	void ReleaseForRegistration() {
		m_object = nullptr;
		m_registeredRef = false;
		if (m_refs == 0)
			delete this;
	}
};

template <class T>
class KCRef
{
	T* m_obj;
#ifdef BN_REF_COUNT_DEBUG
	void* m_assignmentTrace = nullptr;
#endif

public:
	KCRef() : m_obj(NULL) {}

	KCRef(T* obj) : m_obj(obj)
	{
		if (m_obj)
		{
			m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
		}
	}

	KCRef(const KCRef<T>& obj) : m_obj(obj.m_obj)
	{
		if (m_obj)
		{
			m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
		}
	}

	KCRef(KCRef<T>&& other) : m_obj(other.m_obj)
	{
		other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
		m_assignmentTrace = other.m_assignmentTrace;
#endif
	}

	~KCRef()
	{
		if (m_obj)
		{
			m_obj->Release();
#ifdef BN_REF_COUNT_DEBUG
			BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
		}
	}

	KCRef<T>& operator=(const BinaryNinja::Ref<T>& obj)
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

	KCRef<T>& operator=(KCRef<T>&& other)
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

	KCRef<T>& operator=(T* obj)
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

	operator T*() const
	{
		return m_obj;
	}

	T* operator->() const
	{
		return m_obj;
	}

	T& operator*() const
	{
		return *m_obj;
	}

	bool operator!() const
	{
		return m_obj == NULL;
	}

	bool operator==(const T* obj) const
	{
		return T::GetObject(m_obj) == T::GetObject(obj);
	}

	bool operator==(const KCRef<T>& obj) const
	{
		return T::GetObject(m_obj) == T::GetObject(obj.m_obj);
	}

	bool operator!=(const T* obj) const
	{
		return T::GetObject(m_obj) != T::GetObject(obj);
	}

	bool operator!=(const KCRef<T>& obj) const
	{
		return T::GetObject(m_obj) != T::GetObject(obj.m_obj);
	}

	bool operator<(const T* obj) const
	{
		return T::GetObject(m_obj) < T::GetObject(obj);
	}

	bool operator<(const KCRef<T>& obj) const
	{
		return T::GetObject(m_obj) < T::GetObject(obj.m_obj);
	}

	T* GetPtr() const
	{
		return m_obj;
	}
};



namespace KernelCacheAPI {
	struct CacheMappingInfo
	{
		uint64_t vmAddress;
		uint64_t size;
		uint64_t fileOffset;
	};

	struct CacheImage
	{
		uint64_t headerFileAddress;
		uint64_t headerVirtualAddress;
		std::string name;
	};

	struct CacheEntry
	{
		std::string path;
		std::string name;
		BNKernelCacheEntryType entryType;
		std::vector<CacheMappingInfo> mappings;
	};

	struct CacheSymbol
	{
		BNSymbolType type;
		uint64_t address;
		std::string name;
	};

	std::string GetSymbolTypeAsString(const BNSymbolType& type);

	class KernelCacheController : public KCCoreRefCountObject<BNKernelCacheController, BNNewKernelCacheControllerReference, BNFreeKernelCacheControllerReference> {
	public:
		explicit KernelCacheController(BNKernelCacheController* controller);
		static KCRef<KernelCacheController> GetController(BinaryNinja::BinaryView& view);

		// Attempt to load the given image into the view.
		//
		// It is the callers responsibility to run linear sweep and update analysis, as you might want to add
		// multiple images at a time.
		bool ApplyImage(BinaryNinja::BinaryView& view, const CacheImage& image);

		bool IsImageLoaded(const CacheImage& image) const;

		std::optional<CacheImage> GetImageAt(uint64_t address) const;
		std::optional<CacheImage> GetImageContaining(uint64_t address) const;
		std::optional<CacheImage> GetImageWithName(const std::string& name) const;

		std::vector<std::string> GetImageDependencies(const CacheImage& image) const;

		std::optional<CacheSymbol> GetSymbolAt(uint64_t address) const;
		std::optional<CacheSymbol> GetSymbolWithName(const std::string& name) const;

		std::vector<CacheImage> GetImages() const;
		std::vector<CacheImage> GetLoadedImages() const;
		std::vector<CacheSymbol> GetSymbols() const;
	};
}
