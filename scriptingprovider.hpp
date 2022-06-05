#pragma once
#include <string>
#include "refcount.hpp"
#include "scriptingprovider.h"

namespace BinaryNinja {
    class BasicBlock;
    class BinaryView;
    class Function;

	// Scripting Provider
	class ScriptingOutputListener
	{
		BNScriptingOutputListener m_callbacks;

		static void OutputCallback(void* ctxt, const char* text);
		static void ErrorCallback(void* ctxt, const char* text);
		static void InputReadyStateChangedCallback(void* ctxt, BNScriptingProviderInputReadyState state);

	  public:
		ScriptingOutputListener();
		BNScriptingOutputListener& GetCallbacks() { return m_callbacks; }

		virtual void NotifyOutput(const std::string& text);
		virtual void NotifyError(const std::string& text);
		virtual void NotifyInputReadyStateChanged(BNScriptingProviderInputReadyState state);
	};

	class ScriptingProvider;

	class ScriptingInstance :
	    public CoreRefCountObject<BNScriptingInstance, BNNewScriptingInstanceReference, BNFreeScriptingInstance>
	{
	  protected:
		ScriptingInstance(ScriptingProvider* provider);
		ScriptingInstance(BNScriptingInstance* instance);

		static void DestroyInstanceCallback(void* ctxt);
		static BNScriptingProviderExecuteResult ExecuteScriptInputCallback(void* ctxt, const char* input);
		static void CancelScriptInputCallback(void* ctxt);
		static void SetCurrentBinaryViewCallback(void* ctxt, BNBinaryView* view);
		static void SetCurrentFunctionCallback(void* ctxt, BNFunction* func);
		static void SetCurrentBasicBlockCallback(void* ctxt, BNBasicBlock* block);
		static void SetCurrentAddressCallback(void* ctxt, uint64_t addr);
		static void SetCurrentSelectionCallback(void* ctxt, uint64_t begin, uint64_t end);
		static char* CompleteInputCallback(void* ctxt, const char* text, uint64_t state);
		static void StopCallback(void* ctxt);

		virtual void DestroyInstance();

	  public:
		virtual BNScriptingProviderExecuteResult ExecuteScriptInput(const std::string& input) = 0;
		virtual void CancelScriptInput();
		virtual void SetCurrentBinaryView(BinaryView* view);
		virtual void SetCurrentFunction(Function* func);
		virtual void SetCurrentBasicBlock(BasicBlock* block);
		virtual void SetCurrentAddress(uint64_t addr);
		virtual void SetCurrentSelection(uint64_t begin, uint64_t end);
		virtual std::string CompleteInput(const std::string& text, uint64_t state);
		virtual void Stop();

		void Output(const std::string& text);
		void Error(const std::string& text);
		void InputReadyStateChanged(BNScriptingProviderInputReadyState state);
		BNScriptingProviderInputReadyState GetInputReadyState();

		void RegisterOutputListener(ScriptingOutputListener* listener);
		void UnregisterOutputListener(ScriptingOutputListener* listener);

		std::string GetDelimiters();
		void SetDelimiters(const std::string& delimiters);
	};

	class CoreScriptingInstance : public ScriptingInstance
	{
	  public:
		CoreScriptingInstance(BNScriptingInstance* instance);
		virtual ~CoreScriptingInstance() {};

		virtual BNScriptingProviderExecuteResult ExecuteScriptInput(const std::string& input) override;
		virtual void CancelScriptInput() override;
		virtual void SetCurrentBinaryView(BinaryView* view) override;
		virtual void SetCurrentFunction(Function* func) override;
		virtual void SetCurrentBasicBlock(BasicBlock* block) override;
		virtual void SetCurrentAddress(uint64_t addr) override;
		virtual void SetCurrentSelection(uint64_t begin, uint64_t end) override;
		virtual std::string CompleteInput(const std::string& text, uint64_t state) override;
		virtual void Stop() override;
	};

	class ScriptingProvider : public StaticCoreRefCountObject<BNScriptingProvider>
	{
		std::string m_nameForRegister;
		std::string m_apiNameForRegister;

	  protected:
		ScriptingProvider(const std::string& name, const std::string& apiName);
		ScriptingProvider(BNScriptingProvider* provider);

		static BNScriptingInstance* CreateInstanceCallback(void* ctxt);
		static bool LoadModuleCallback(void* ctxt, const char* repository, const char* module, bool force);
		static bool InstallModulesCallback(void* ctxt, const char* modules);

	  public:
		virtual Ref<ScriptingInstance> CreateNewInstance() = 0;
		virtual bool LoadModule(const std::string& repository, const std::string& module, bool force) = 0;
		virtual bool InstallModules(const std::string& modules) = 0;

		std::string GetName();
		std::string GetAPIName();

		static std::vector<Ref<ScriptingProvider>> GetList();
		static Ref<ScriptingProvider> GetByName(const std::string& name);
		static Ref<ScriptingProvider> GetByAPIName(const std::string& apiName);
		static void Register(ScriptingProvider* provider);
	};

	class CoreScriptingProvider : public ScriptingProvider
	{
	  public:
		CoreScriptingProvider(BNScriptingProvider* provider);
		virtual Ref<ScriptingInstance> CreateNewInstance() override;
		virtual bool LoadModule(const std::string& repository, const std::string& module, bool force) override;
		virtual bool InstallModules(const std::string& modules) override;
	};
}