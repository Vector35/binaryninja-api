#pragma once

#include <binaryninjaapi.h>
#include "sharedcachecore.h"

#include <memory>

template<class T>
class DSCRefCountObject {
	void AddRefInternal() { m_refs.fetch_add(1); }

	void ReleaseInternal() {
		if (m_refs.fetch_sub(1) == 1)
			delete this;
	}

public:
	std::atomic<int> m_refs;
	T *m_object;

	DSCRefCountObject() : m_refs(0), m_object(nullptr) {}

	virtual ~DSCRefCountObject() = default;

	T *GetObject() const { return m_object; }

	static T *GetObject(DSCRefCountObject *obj) {
		if (!obj)
			return nullptr;
		return obj->GetObject();
	}

	void AddRef() { AddRefInternal(); }

	void Release() { ReleaseInternal(); }

	void AddRefForRegistration() { AddRefInternal(); }
};


template<class T, T *(*AddObjectReference)(T *), void (*FreeObjectReference)(T *)>
class DSCCoreRefCountObject {
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

	DSCCoreRefCountObject() : m_refs(0), m_object(nullptr) {}

	virtual ~DSCCoreRefCountObject() = default;

	T *GetObject() const { return m_object; }

	static T *GetObject(DSCCoreRefCountObject *obj) {
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
class DSCRef
{
	T* m_obj;
#ifdef BN_REF_COUNT_DEBUG
	void* m_assignmentTrace = nullptr;
#endif

public:
	DSCRef() : m_obj(NULL) {}

	DSCRef(T* obj) : m_obj(obj)
	{
		if (m_obj)
		{
			m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
		}
	}

	DSCRef(const DSCRef<T>& obj) : m_obj(obj.m_obj)
	{
		if (m_obj)
		{
			m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
		}
	}

	DSCRef(DSCRef<T>&& other) : m_obj(other.m_obj)
	{
		other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
		m_assignmentTrace = other.m_assignmentTrace;
#endif
	}

	~DSCRef()
	{
		if (m_obj)
		{
			m_obj->Release();
#ifdef BN_REF_COUNT_DEBUG
			BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
		}
	}

	DSCRef<T>& operator=(const BinaryNinja::Ref<T>& obj)
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

	DSCRef<T>& operator=(DSCRef<T>&& other)
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

	DSCRef<T>& operator=(T* obj)
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

	bool operator==(const DSCRef<T>& obj) const
	{
		return T::GetObject(m_obj) == T::GetObject(obj.m_obj);
	}

	bool operator!=(const T* obj) const
	{
		return T::GetObject(m_obj) != T::GetObject(obj);
	}

	bool operator!=(const DSCRef<T>& obj) const
	{
		return T::GetObject(m_obj) != T::GetObject(obj.m_obj);
	}

	bool operator<(const T* obj) const
	{
		return T::GetObject(m_obj) < T::GetObject(obj);
	}

	bool operator<(const DSCRef<T>& obj) const
	{
		return T::GetObject(m_obj) < T::GetObject(obj.m_obj);
	}

	T* GetPtr() const
	{
		return m_obj;
	}
};



// TODO: replace namespace?
namespace SharedCacheAPI {
	struct CacheRegion
	{
		BNSharedCacheRegionType type;
		std::string name;
		uint64_t start;
		uint64_t size;
		std::optional<uint64_t> imageStart;
		BNSegmentFlag flags;
	};

	std::string GetRegionTypeAsString(const BNSharedCacheRegionType& type);

	struct CacheMappingInfo
	{
		uint64_t vmAddress;
		uint64_t size;
		uint64_t fileOffset;
	};

	struct CacheImage
	{
		uint64_t headerAddress;
		std::string name;
		std::vector<uint64_t> regionStarts;
	};

	struct CacheEntry
	{
		std::string path;
		std::string name;
		BNSharedCacheEntryType entryType;
		std::vector<CacheMappingInfo> mappings;
	};

	struct CacheSymbol
	{
		BNSymbolType type;
		BNSymbolBinding binding = NoBinding;
		uint64_t address;
		std::string name;
	};

	std::string GetSymbolTypeAsString(const BNSymbolType& type);

	struct CacheString
	{
		// UTF-8 display text, truncated.
		std::string text;
		uint64_t address;
		uint64_t regionStart;
		// Header address of the image owning the string's region, or 0 if it is not part of an image.
		uint64_t imageStart;
		BNStringType type;
		// Length of the string in the cache, in bytes.
		uint32_t rawLength;
	};

	class CacheStringScanner
	{
		BNSharedCacheStringScanner* m_object = nullptr;

	public:
		explicit CacheStringScanner(BNSharedCacheStringScanner* scanner);
		~CacheStringScanner();

		CacheStringScanner(const CacheStringScanner&) = delete;
		CacheStringScanner& operator=(const CacheStringScanner&) = delete;
		CacheStringScanner(CacheStringScanner&& other) noexcept;
		CacheStringScanner& operator=(CacheStringScanner&& other) noexcept;

		bool Start();
		bool IsComplete() const;
		std::pair<uint64_t, uint64_t> GetProgress() const;
		uint64_t GetStringCount() const;
		std::vector<CacheString> TakeStrings(uint64_t maxCount);
	};

	class SharedCacheController : public DSCCoreRefCountObject<BNSharedCacheController, BNNewSharedCacheControllerReference, BNFreeSharedCacheControllerReference> {
	public:
		explicit SharedCacheController(BNSharedCacheController* controller);
		static DSCRef<SharedCacheController> GetController(BinaryNinja::BinaryView& view);

		bool ApplyRegion(BinaryNinja::BinaryView& view, const CacheRegion& region);

		// Attempt to load the given image into the view.
		//
		// It is the callers responsibility to run linear sweep and update analysis, as you might want to add
		// multiple images at a time.
		bool ApplyImage(BinaryNinja::BinaryView& view, const CacheImage& image);

		bool IsRegionLoaded(const CacheRegion& region) const;
		bool IsImageLoaded(const CacheImage& image) const;

		std::optional<CacheRegion> GetRegionAt(uint64_t address) const;
		std::optional<CacheRegion> GetRegionContaining(uint64_t address) const;

		std::optional<CacheImage> GetImageAt(uint64_t address) const;
		std::optional<CacheImage> GetImageContaining(uint64_t address) const;
		std::optional<CacheImage> GetImageWithName(const std::string& name) const;

		std::vector<std::string> GetImageDependencies(const CacheImage& image) const;

		std::optional<CacheSymbol> GetSymbolAt(uint64_t address) const;
		std::optional<CacheSymbol> GetSymbolWithName(const std::string& name) const;

		std::vector<CacheEntry> GetEntries() const;
		std::vector<CacheRegion> GetRegions() const;
		std::vector<CacheRegion> GetLoadedRegions() const;
		std::vector<CacheImage> GetImages() const;
		std::vector<CacheImage> GetLoadedImages() const;
		std::vector<CacheSymbol> GetSymbols() const;

		std::unique_ptr<CacheStringScanner> CreateStringScanner() const;
	};
}
