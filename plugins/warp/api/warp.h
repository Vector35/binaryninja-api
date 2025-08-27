#pragma once

#include <binaryninjaapi.h>
#include "warpcore.h"

template<class T, T *(*AddObjectReference)(T *), void (*FreeObjectReference)(T *)>
class WarpRefCountObject
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
	T *m_object;

	WarpRefCountObject() : m_refs(0), m_object(nullptr)
	{
	}

	virtual ~WarpRefCountObject() = default;

	T *GetObject() const { return m_object; }

	static T *GetObject(WarpRefCountObject *obj)
	{
		if (!obj)
			return nullptr;
		return obj->GetObject();
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

namespace Warp {
	template<class T>
	class Ref
	{
		T *m_obj;
#ifdef BN_REF_COUNT_DEBUG
		void *m_assignmentTrace = nullptr;
#endif

	public:
		Ref() : m_obj(NULL)
		{
		}

		Ref(T *obj) : m_obj(obj)
		{
			if (m_obj)
			{
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		Ref(const Ref &obj) : m_obj(obj.m_obj)
		{
			if (m_obj)
			{
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		Ref(Ref &&other) : m_obj(other.m_obj)
		{
			other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = other.m_assignmentTrace;
#endif
		}

		~Ref()
		{
			if (m_obj)
			{
				m_obj->Release();
#ifdef BN_REF_COUNT_DEBUG
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
			}
		}

		Ref<T> &operator=(const Ref<T> &obj)
		{
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj.m_obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T *oldObj = m_obj;
			m_obj = obj.m_obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		Ref<T> &operator=(Ref<T> &&other)
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

		Ref<T> &operator=(T *obj)
		{
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T *oldObj = m_obj;
			m_obj = obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		operator T *() const
		{
			return m_obj;
		}

		T *operator->() const
		{
			return m_obj;
		}

		T &operator*() const
		{
			return *m_obj;
		}

		bool operator!() const
		{
			return m_obj == NULL;
		}

		bool operator==(const T *obj) const
		{
			return T::GetObject(m_obj) == T::GetObject(obj);
		}

		bool operator==(const Ref<T> &obj) const
		{
			return T::GetObject(m_obj) == T::GetObject(obj.m_obj);
		}

		bool operator!=(const T *obj) const
		{
			return T::GetObject(m_obj) != T::GetObject(obj);
		}

		bool operator!=(const Ref<T> &obj) const
		{
			return T::GetObject(m_obj) != T::GetObject(obj.m_obj);
		}

		bool operator<(const T *obj) const
		{
			return T::GetObject(m_obj) < T::GetObject(obj);
		}

		bool operator<(const Ref<T> &obj) const
		{
			return T::GetObject(m_obj) < T::GetObject(obj.m_obj);
		}

		T *GetPtr() const
		{
			return m_obj;
		}
	};

	class WarpUUID
	{
		BNWARPUUID uuid;

	public:
		WarpUUID() = default;

		WarpUUID(BNWARPUUID uuid) : uuid(uuid)
		{
		}

		static std::optional<WarpUUID> FromString(const std::string &str);

		std::string ToString() const;

		bool operator==(const WarpUUID &other) const
		{
			return BNWARPUUIDEqual(&uuid, &other.uuid);
		}

		bool operator!=(const WarpUUID &other) const
		{
			return !(*this == other);
		}

		BNWARPUUID *RawMut()
		{
			return &uuid;
		}

		const BNWARPUUID *Raw() const
		{
			return &uuid;
		}
	};

	typedef WarpUUID Source;
	typedef WarpUUID BasicBlockGUID;
	typedef WarpUUID FunctionGUID;
	typedef WarpUUID ConstraintGUID;
	typedef WarpUUID TypeGUID;
	typedef std::string SourceTag;

	class Target : public WarpRefCountObject<BNWARPTarget, BNWARPNewTargetReference,
				BNWARPFreeTargetReference>
	{
	public:
		explicit Target(BNWARPTarget *target);

		static Ref<Target> FromPlatform(const BinaryNinja::Platform &platform);
	};

	struct Constraint
	{
		ConstraintGUID guid;
		std::optional<int64_t> offset;

		Constraint(ConstraintGUID guid, std::optional<int64_t> offset);

		static Constraint FromAPIObject(BNWARPConstraint *constraint);
	};

	struct FunctionComment
	{
		std::string text;
		int64_t offset;

		FunctionComment(std::string text, int64_t offset);

		static FunctionComment FromAPIObject(BNWARPFunctionComment *comment);
	};

	class Function : public WarpRefCountObject<BNWARPFunction, BNWARPNewFunctionReference, BNWARPFreeFunctionReference>
	{
	public:
		explicit Function(BNWARPFunction *function);

		bool operator==(const Function &other) const
		{
			return BNWARPFunctionsEqual(m_object, other.m_object);
		}

		FunctionGUID GetGUID() const;

		std::string GetSymbolName() const;

		BinaryNinja::Ref<BinaryNinja::Symbol> GetSymbol(const BinaryNinja::Function &function) const;

		BinaryNinja::Ref<BinaryNinja::Type> GetType(const BinaryNinja::Function &function) const;

		std::vector<Constraint> GetConstraints() const;

		std::vector<FunctionComment> GetComments() const;

		static Ref<Function> Get(const BinaryNinja::Function &function);

		static Ref<Function> GetMatched(const BinaryNinja::Function &function);

		void Apply(const BinaryNinja::Function &function) const;

		static void RemoveMatch(const BinaryNinja::Function &function);
	};

	class ContainerSearchQuery : public WarpRefCountObject<BNWARPContainerSearchQuery,
				BNWARPNewContainerSearchQueryReference,
				BNWARPFreeContainerSearchQueryReference>
	{
	public:
		explicit ContainerSearchQuery(BNWARPContainerSearchQuery *query);

		explicit ContainerSearchQuery(const std::string &query);

		ContainerSearchQuery(const std::string &query, const Source &source);

		ContainerSearchQuery(const std::string &query, size_t offset, size_t limit,
		                     const std::optional<Source> &source = std::nullopt,
		                     const std::vector<SourceTag> &tags = {});
	};

	class ContainerSearchItem : public WarpRefCountObject<BNWARPContainerSearchItem,
				BNWARPNewContainerSearchItemReference,
				BNWARPFreeContainerSearchItemReference>
	{
	public:
		explicit ContainerSearchItem(BNWARPContainerSearchItem *item);

		BNWARPContainerSearchItemKind GetKind() const;

		Source GetSource() const;

		BinaryNinja::Ref<BinaryNinja::Type> GetType(const BinaryNinja::Ref<BinaryNinja::Architecture> &arch) const;

		std::string GetName() const;

		Ref<Function> GetFunction() const;
	};

	struct ContainerSearchResponse
	{
		std::vector<Ref<ContainerSearchItem> > items;
		size_t offset;
		size_t total;

		ContainerSearchResponse(std::vector<Ref<ContainerSearchItem> > &&items, size_t offset, size_t total);

		static ContainerSearchResponse FromAPIObject(BNWARPContainerSearchResponse *response);
	};

	class Container : public WarpRefCountObject<BNWARPContainer, BNWARPNewContainerReference,
				BNWARPFreeContainerReference>
	{
	public:
		explicit Container(BNWARPContainer *container);

		/// Retrieve all available containers.
		static std::vector<Ref<Container> > All();

		std::string GetName() const;

		std::vector<Source> GetSources() const;

		std::optional<Source> AddSource(const std::string &sourcePath) const;

		bool CommitSource(const Source &source) const;

		bool IsSourceUncommitted(const Source &source) const;

		bool IsSourceWritable(const Source &source) const;

		std::optional<std::string> SourcePath(const Source &source) const;

		bool AddFunctions(const Target &target, const Source &source,
		                  const std::vector<Ref<Function> > &functions) const;

		bool AddTypes(const BinaryNinja::BinaryView &view, const Source &source,
		              const std::vector<BinaryNinja::Ref<BinaryNinja::Type> > &types) const;

		bool RemoveFunctions(const Target &target, const Source &source,
		                     const std::vector<Ref<Function> > &functions) const;

		bool RemoveTypes(const Source &source, const std::vector<TypeGUID> &guids) const;

		void FetchFunctions(const Target &target, const std::vector<FunctionGUID> &guids, const std::vector<SourceTag> &tags = {}) const;

		std::vector<Source> GetSourcesWithFunctionGUID(const Target &target, const FunctionGUID &guid) const;

		std::vector<Source> GetSourcesWithTypeGUID(const TypeGUID &guid) const;

		std::vector<Ref<Function> > GetFunctionsWithGUID(const Target &target, const Source &source,
		                                                 const FunctionGUID &guid) const;

		BinaryNinja::Ref<BinaryNinja::Type> GetTypeWithGUID(const BinaryNinja::Architecture &arch, const Source &source,
		                                                    const TypeGUID &guid) const;

		std::vector<TypeGUID> GetTypeGUIDsWithName(const Source &source, const std::string &name) const;

		std::optional<ContainerSearchResponse> Search(const ContainerSearchQuery &query) const;
	};

	void RunMatcher(const BinaryNinja::BinaryView &view);

	bool IsInstructionVariant(const BinaryNinja::LowLevelILFunction &function, BinaryNinja::ExprId idx);

	bool IsInstructionBlacklisted(const BinaryNinja::LowLevelILFunction &function, BinaryNinja::ExprId idx);

	std::optional<FunctionGUID> GetAnalysisFunctionGUID(const BinaryNinja::Function &function);

	std::optional<BasicBlockGUID> GetBasicBlockGUID(const BinaryNinja::BasicBlock &basicBlock);
}

template<> struct std::hash<Warp::WarpUUID>
{
	size_t operator()(Warp::WarpUUID const& item) const noexcept
	{
		// TODO: Use the raw bytes instead.
		return std::hash<std::string>()(item.ToString());
	}
};