#pragma once
#include <string>
#include <unordered_map>

#include "refcount.hpp"
#include "binaryninjacore/websocketprovider.h"

namespace BinaryNinja {

	// WebsocketProvider
	class WebsocketProvider;

	class WebsocketClient :
	    public CoreRefCountObject<BNWebsocketClient, BNNewWebsocketClientReference, BNFreeWebsocketClient>
	{
	  protected:
		WebsocketClient(WebsocketProvider* provider);
		WebsocketClient(BNWebsocketClient* instance);

		static void DestroyClientCallback(void* ctxt);
		static bool ConnectCallback(void* ctxt, const char* host, uint64_t headerCount, const char* const* headerKeys,
		    const char* const* headerValues);
		static bool WriteCallback(const uint8_t* data, uint64_t len, void* ctxt);
		static bool DisconnectCallback(void* ctxt);
		static void ErrorCallback(const char* msg, void* ctxt);
		bool ReadData(uint8_t* data, uint64_t len);

		/*!
		    Cleanup any resources created by the client
		 */
		virtual void DestroyClient();
		/*!
		    Virtual method for performing the connection, overridden by a subclass.
		    \param host Full url with scheme, domain, optionally port, and path
		    \param headers HTTP header keys and values
		    \return True if the connection has started, but not necessarily if it succeeded
		 */
		virtual bool Connect(const std::string& host, const std::unordered_map<std::string, std::string>& headers) = 0;

	  public:
		/*!
		    Connect to a given url, asynchronously. The connection will be run in a separate thread managed by the
		   websocket provider.

		    Callbacks will be called **on the thread of the connection**, so be sure to ExecuteOnMainThread any
		   long-running or gui operations in the callbacks.

		    If the connection succeeds, connectedCallback will be called. On normal termination, disconnectedCallback
		   will be called. If the connection succeeds, but later fails, disconnectedCallback will not be called, and
		   errorCallback will be called instead. If the connection fails, neither connectedCallback nor
		   disconnectedCallback will be called, and errorCallback will be called instead.

		    If connectedCallback or readCallback return false, the connection will be aborted.

		    \param host Full url with scheme, domain, optionally port, and path
		    \param headers HTTP header keys and values
		    \param callbacks Structure with callbacks for various websocket events
		    \return True if the connection has started, but not necessarily if it succeeded
		 */
		bool Connect(const std::string& host, const std::unordered_map<std::string, std::string>& headers,
		    BNWebsocketClientOutputCallbacks* callbacks);

		/*!
		    Write some data to the websocket
		    \param data Data to write
		    \return True if successful
		 */
		virtual bool Write(const std::vector<uint8_t>& data) = 0;
		/*!
		    Disconnect the websocket
		    \return True if successful
		 */
		virtual bool Disconnect() = 0;
	};

	class CoreWebsocketClient : public WebsocketClient
	{
	  public:
		CoreWebsocketClient(BNWebsocketClient* instance);
		virtual ~CoreWebsocketClient() {};

		virtual bool Connect(
		    const std::string& host, const std::unordered_map<std::string, std::string>& headers) override;
		virtual bool Write(const std::vector<uint8_t>& data) override;
		virtual bool Disconnect() override;
	};

	class WebsocketProvider : public StaticCoreRefCountObject<BNWebsocketProvider>
	{
		std::string m_nameForRegister;

	  protected:
		WebsocketProvider(const std::string& name);
		WebsocketProvider(BNWebsocketProvider* provider);

		static BNWebsocketClient* CreateClientCallback(void* ctxt);

	  public:
		virtual Ref<WebsocketClient> CreateNewClient() = 0;

		static std::vector<Ref<WebsocketProvider>> GetList();
		static Ref<WebsocketProvider> GetByName(const std::string& name);
		static void Register(WebsocketProvider* provider);
	};

	class CoreWebsocketProvider : public WebsocketProvider
	{
	  public:
		CoreWebsocketProvider(BNWebsocketProvider* provider);
		virtual Ref<WebsocketClient> CreateNewClient() override;
	};

}