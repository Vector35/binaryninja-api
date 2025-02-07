#pragma once

#include <QThread>

#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <variant>
#include <vector>
#include "binaryninjaapi.h"
#include "uitypes.h"


class NotificationEvent
{
public:

	struct BinaryDataChangeInfo
	{
		uint64_t offset;
		size_t len;

		BinaryDataChangeInfo() : offset(0), len(0) {}
		BinaryDataChangeInfo(uint64_t offset, size_t len) : offset(offset), len(len) {}
	};

	class SymbolInfo
	{
		BNSymbolType m_symbolType;
		BNSymbolBinding m_symbolBinding;
		std::string m_rawName;
		std::string m_shortName;
		std::string m_fullName;
		uint64_t m_address;
		bool m_gratuitous;
		bool m_autoDefined;

	public:
		SymbolInfo(BNSymbolType type, const std::string& name, uint64_t address) {
			m_symbolType = type;
			m_symbolBinding = NoBinding;
			m_rawName = name;
			m_address = address;
			m_gratuitous = true;
			m_autoDefined = true;
		}

		SymbolInfo(const SymbolRef& symbol) {
			m_symbolType = symbol->GetType();
			m_symbolBinding = symbol->GetBinding();
			setNames(symbol->GetRawName(), symbol->GetShortName(), symbol->GetFullName());
			m_address = symbol->GetAddress();
			m_gratuitous = false;
			m_autoDefined = symbol->IsAutoDefined();
		}

		BNSymbolType getType() const { return m_symbolType; }
		uint64_t getAddress() const { return m_address; }
		BNSymbolBinding getBinding() const { return m_symbolBinding; }
		bool isGratuitous() const { return m_gratuitous; }
		bool isAutoDefined() const { return m_autoDefined; }

		const std::string& getRawName() const { return m_rawName; }
		const std::string& getShortName() const { return m_shortName.empty() ? m_rawName : m_shortName; }
		const std::string& getFullName() const { return m_fullName.empty() ? m_rawName : m_fullName; }

		void setNames(const std::string& rawName, const std::string& shortName, const std::string& fullName) {
			m_rawName = rawName;
			if (!shortName.empty() && shortName != rawName)
				m_shortName = shortName;
			if (!fullName.empty() && fullName != rawName)
				m_fullName = fullName;
		}
	};

	struct StringInfo
	{
		BNStringType type;
		uint64_t offset;
		size_t len;

		StringInfo() : type(BNStringType::AsciiString), offset(0), len(0) {}
		StringInfo(BNStringType type, uint64_t offset, size_t len): type(type), offset(offset), len(len) {}
	};

	struct TypeChangeInfo
	{
		BinaryNinja::QualifiedName name;
		TypeRef type;
		uint64_t offset;

		TypeChangeInfo() : offset(0) {}
		TypeChangeInfo(const BinaryNinja::QualifiedName& name, TypeRef type): name(name), type(type), offset(0) {}
		TypeChangeInfo(const BinaryNinja::QualifiedName& name, uint64_t offset): name(name), offset(offset) {}
	};

	struct ComponentInfo
	{
		ComponentRef component;
		ComponentRef parent;
		FunctionRef function;
		BinaryNinja::DataVariable dataVar;

		ComponentInfo() {};
		ComponentInfo(BinaryNinja::Component* component) : component(component) {};
		ComponentInfo(BinaryNinja::Component* component, BinaryNinja::Component* parent) : component(component), parent(parent) {};
		ComponentInfo(BinaryNinja::Component* component, FunctionRef function) : component(component), function(function) {};
		ComponentInfo(BinaryNinja::Component* component, const BinaryNinja::DataVariable& dataVar) : component(component), dataVar(dataVar) {};
	};

	struct TypeArchiveInfo
	{
		std::string id;
		std::string path;

		TypeArchiveInfo() {};
		TypeArchiveInfo(const std::string& id, const std::string& path) : id(id), path(path) {};
	};

private:
	using NotificationType = BinaryNinja::BinaryDataNotification::NotificationType;
	using NotificationTypes = BinaryNinja::BinaryDataNotification::NotificationTypes;

	NotificationType m_source;
	SymbolRef m_symbol;
	std::unique_ptr<SymbolInfo> m_symbolInfo;
	std::variant<std::monostate, BinaryDataChangeInfo, FunctionRef, BinaryNinja::DataVariable, TagTypeRef,
		BinaryNinja::TagReference, StringInfo, TypeChangeInfo, SegmentRef, SectionRef, ComponentInfo,
		ExternalLibraryRef, ExternalLocationRef, TypeArchiveInfo, TypeArchiveRef, UndoEntryRef> m_object;

public:
	NotificationEvent(NotificationType source): m_source(source) { }
	NotificationEvent(NotificationType source, BinaryNinja::Symbol* symbol): m_source(source), m_symbol(symbol) { }
	NotificationEvent(NotificationType source, BinaryDataChangeInfo&& binaryDataChange): m_source(source), m_object(std::move(binaryDataChange)) { }
	NotificationEvent(NotificationType source, BinaryNinja::Function* function): m_source(source), m_object(function) { }
	NotificationEvent(NotificationType source, const BinaryNinja::DataVariable& dataVariable): m_source(source), m_object(dataVariable) { }
	NotificationEvent(NotificationType source, BinaryNinja::TagType* tagType): m_source(source), m_object(tagType) { }
	NotificationEvent(NotificationType source, const BinaryNinja::TagReference& tagRef): m_source(source), m_object(tagRef) { }
	NotificationEvent(NotificationType source, StringInfo&& stringInfo): m_source(source), m_object(std::move(stringInfo)) { }
	NotificationEvent(NotificationType source, TypeChangeInfo&& typeChangeInfo): m_source(source), m_object(std::move(typeChangeInfo)) { }
	NotificationEvent(NotificationType source, BinaryNinja::Segment* segment): m_source(source), m_object(segment) { }
	NotificationEvent(NotificationType source, BinaryNinja::Section* section): m_source(source), m_object(section) { }
	NotificationEvent(NotificationType source, ComponentInfo&& componentInfo): m_source(source), m_object(std::move(componentInfo)) { }
	NotificationEvent(NotificationType source, BinaryNinja::ExternalLibrary* library): m_source(source), m_object(library) { }
	NotificationEvent(NotificationType source, BinaryNinja::ExternalLocation* location): m_source(source), m_object(location) { }
	NotificationEvent(NotificationType source, TypeArchiveInfo&& typeArchiveInfo): m_source(source), m_object(std::move(typeArchiveInfo)) { }
	NotificationEvent(NotificationType source, BinaryNinja::TypeArchive* archive): m_source(source), m_object(archive) { }
	NotificationEvent(NotificationType source, BinaryNinja::UndoEntry* entry): m_source(source), m_object(entry) { }

	void cacheSymbolInfo();
	SymbolInfo* getSymbolInfo() const { return m_symbolInfo.get(); }
	std::unique_ptr<SymbolInfo> takeSymbolInfo() { return std::move(m_symbolInfo); }

	bool hasDataVariableObject() const { return std::holds_alternative<BinaryNinja::DataVariable>(m_object); }
	bool hasFunctionObject() const { return std::holds_alternative<FunctionRef>(m_object); }
	bool hasObject() const { return !std::holds_alternative<std::monostate>(m_object); }

	template <typename Visitor>
	constexpr decltype(auto) getObject(Visitor&& visitor) { return std::visit(std::forward<Visitor>(visitor), m_object); }

	template <typename T>
	void setObject(const T& obj) { m_object = obj; }

	void addSource(NotificationType source) { m_source = static_cast<NotificationType>(static_cast<uint64_t>(m_source) | static_cast<uint64_t>(source)); }
	NotificationType getSource() const { return m_source; }
	NotificationTypes getSources() const { return static_cast<NotificationTypes>(m_source); }
	bool isObjectRemoval() const { return (m_source & (NotificationType::DataVariableRemoved | NotificationType::FunctionRemoved | NotificationType::StringRemoved)); }
	bool isRemoval() const { return (m_source & (NotificationType::DataVariableRemoved | NotificationType::FunctionRemoved | NotificationType::SymbolRemoved | NotificationType::StringRemoved)); }
};


class NotificationsWorker: public QThread, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	class AnalysisCache: public BinaryNinja::RefCountObject
	{
		BinaryViewRef m_view;
		NotificationTypes m_notifications;
		bool m_enable;
		std::vector<SymbolRef> m_symbols;
		std::vector<FunctionRef> m_functions;
		std::map<uint64_t, BinaryNinja::DataVariable> m_dataVariables;
		std::unordered_map<uint64_t, NotificationEvent> m_coalesced;

	public:
		AnalysisCache(BinaryViewRef view,  NotificationTypes notifications, bool enableAnalysisCaching): m_view(view), m_notifications(notifications), m_enable(enableAnalysisCaching) { }

		void fetch();
		void coalesce();
		std::deque<std::vector<NotificationEvent>> generate();
	};

	BinaryViewRef m_view = nullptr;
	NotificationTypes m_notifications;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;
	bool m_registered = false;
	bool m_request = false;
	BinaryNinja::Ref<AnalysisCache> m_analysisCache = nullptr;
	bool m_analysisCaching = true;
	bool m_eventQueuing = true;
	std::function<void(bool refresh, std::vector<NotificationEvent>&&)> m_updateHandler;

	std::mutex m_mutex;
	std::condition_variable m_condition;
	std::condition_variable m_requestCondition;
	std::atomic<bool> m_done = false;

	std::vector<NotificationEvent> m_ingressQueue;
	std::deque<std::vector<NotificationEvent>> m_egressQueue;

	void run() override;

public:
	NotificationsWorker() = delete;
	NotificationsWorker(BinaryViewRef view, NotificationTypes notifications): BinaryDataNotification(notifications), m_view(view), m_notifications(notifications) {
		m_logger = BinaryNinja::LogRegistry::CreateLogger("NotificationsDispatcher");
	}

	void setAnalysisCachingEnabled(bool enable) { m_analysisCaching = enable; }
	void setNotificationEventQueuing(bool enable) { m_eventQueuing = enable; }
	void setUpdateHandler(std::function<void(bool refresh, std::vector<NotificationEvent>&&)>&& updateHandler) { m_updateHandler = std::move(updateHandler); }

	void asyncRefresh();
	void cancel();

	template <typename... Args>
	void enqueue(NotificationType notification, Args&&... args) {
		if (m_eventQueuing)
			m_ingressQueue.emplace_back(notification, std::forward<Args>(args)...);
		else
		{
			NotificationEvent& event = m_ingressQueue.empty() ? m_ingressQueue.emplace_back(notification) : m_ingressQueue.front();
			event.addSource(notification);
		}
	}

	uint64_t OnNotificationBarrier(BinaryNinja::BinaryView* view) override;

	void OnBinaryDataWritten(BinaryNinja::BinaryView* view, uint64_t offset, size_t len) override;
	void OnBinaryDataInserted(BinaryNinja::BinaryView* view, uint64_t offset, size_t len) override;
	void OnBinaryDataRemoved(BinaryNinja::BinaryView* view, uint64_t offset, uint64_t len) override;

	void OnAnalysisFunctionAdded(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;
	void OnAnalysisFunctionRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;
	void OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;
	void OnAnalysisFunctionUpdateRequested(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;

	void OnDataVariableAdded(BinaryNinja::BinaryView* view, const BinaryNinja::DataVariable& var) override;
	void OnDataVariableRemoved(BinaryNinja::BinaryView* view, const BinaryNinja::DataVariable& var) override;
	void OnDataVariableUpdated(BinaryNinja::BinaryView* view, const BinaryNinja::DataVariable& var) override;
	void OnDataMetadataUpdated(BinaryNinja::BinaryView* view, uint64_t offset) override;

	void OnTagTypeUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Ref<BinaryNinja::TagType> tagTypeRef) override;
	void OnTagAdded(BinaryNinja::BinaryView* view, const BinaryNinja::TagReference& tagRef) override;
	void OnTagRemoved(BinaryNinja::BinaryView* view, const BinaryNinja::TagReference& tagRef) override;
	void OnTagUpdated(BinaryNinja::BinaryView* view, const BinaryNinja::TagReference& tagRef) override;

	void OnSymbolAdded(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym) override;
	void OnSymbolRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym) override;
	void OnSymbolUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Symbol* sym) override;

	void OnStringFound(BinaryNinja::BinaryView* view, BNStringType type, uint64_t offset, size_t len) override;
	void OnStringRemoved(BinaryNinja::BinaryView* view, BNStringType type, uint64_t offset, size_t len) override;

	void OnTypeDefined(BinaryNinja::BinaryView* view, const BinaryNinja::QualifiedName& name, BinaryNinja::Type* type) override;
	void OnTypeUndefined(BinaryNinja::BinaryView* view, const BinaryNinja::QualifiedName& name, BinaryNinja::Type* type) override;
	void OnTypeReferenceChanged(BinaryNinja::BinaryView* view, const BinaryNinja::QualifiedName& name, BinaryNinja::Type* type) override;
	void OnTypeFieldReferenceChanged(BinaryNinja::BinaryView* view, const BinaryNinja::QualifiedName& name, uint64_t offset) override;

	void OnSegmentAdded(BinaryNinja::BinaryView* view, BinaryNinja::Segment* segment) override;
	void OnSegmentRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Segment* segment) override;
	void OnSegmentUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Segment* segment) override;

	void OnSectionAdded(BinaryNinja::BinaryView* view, BinaryNinja::Section* section) override;
	void OnSectionRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Section* section) override;
	void OnSectionUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Section* section) override;

	void OnComponentAdded(BinaryNinja::BinaryView* view, BinaryNinja::Component* component) override;
	void OnComponentRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Component* component, BinaryNinja::Component*) override;
	void OnComponentNameUpdated(BinaryNinja::BinaryView* view, std::string& previousName, BinaryNinja::Component* component) override;
	void OnComponentMoved(BinaryNinja::BinaryView* view, BinaryNinja::Component* parent, BinaryNinja::Component*, BinaryNinja::Component* component) override;
	void OnComponentFunctionAdded(BinaryNinja::BinaryView* view, BinaryNinja::Component* component, BinaryNinja::Function* func) override;
	void OnComponentFunctionRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Component* component, BinaryNinja::Function* func) override;
	void OnComponentDataVariableAdded(BinaryNinja::BinaryView* view, BinaryNinja::Component* component, const BinaryNinja::DataVariable& var) override;
	void OnComponentDataVariableRemoved(BinaryNinja::BinaryView* view, BinaryNinja::Component* component, const BinaryNinja::DataVariable& var) override;

	void OnExternalLibraryAdded(BinaryNinja::BinaryView* data, BinaryNinja::ExternalLibrary* library) override;
	void OnExternalLibraryRemoved(BinaryNinja::BinaryView* data, BinaryNinja::ExternalLibrary* library) override;
	void OnExternalLibraryUpdated(BinaryNinja::BinaryView* data, BinaryNinja::ExternalLibrary* library) override;

	void OnExternalLocationAdded(BinaryNinja::BinaryView* data, BinaryNinja::ExternalLocation* location) override;
	void OnExternalLocationRemoved(BinaryNinja::BinaryView* data, BinaryNinja::ExternalLocation* location) override;
	void OnExternalLocationUpdated(BinaryNinja::BinaryView* data, BinaryNinja::ExternalLocation* location) override;

	void OnTypeArchiveAttached(BinaryNinja::BinaryView* data, const std::string& id, const std::string& path) override;
	void OnTypeArchiveDetached(BinaryNinja::BinaryView* data, const std::string& id, const std::string& path) override;
	void OnTypeArchiveConnected(BinaryNinja::BinaryView* data, BinaryNinja::TypeArchive* archive) override;
	void OnTypeArchiveDisconnected(BinaryNinja::BinaryView* data, BinaryNinja::TypeArchive* archive) override;

	void OnUndoEntryAdded(BinaryNinja::BinaryView* data, BinaryNinja::UndoEntry* entry) override;
	void OnUndoEntryTaken(BinaryNinja::BinaryView* data, BinaryNinja::UndoEntry* entry) override;
	void OnRedoEntryTaken(BinaryNinja::BinaryView* data, BinaryNinja::UndoEntry* entry) override;
};


class NotificationsDispatcher: public QObject
{
	Q_OBJECT

	std::unique_ptr<NotificationsWorker> m_worker;

public:
	NotificationsDispatcher(QObject* parent, BinaryViewRef view, BinaryNinja::BinaryDataNotification::NotificationTypes notifications);
	~NotificationsDispatcher();

	void setAnalysisCachingEnabled(bool enable) { m_worker->setAnalysisCachingEnabled(enable); }
	void setNotificationEventQueuing(bool enable) { m_worker->setNotificationEventQueuing(enable); }
	void setUpdateHandler(std::function<void(bool refresh, std::vector<NotificationEvent>&&)>&& updateHandler) { m_worker->setUpdateHandler(std::move(updateHandler)); }

	void asyncRefresh() { m_worker->asyncRefresh(); }
};

