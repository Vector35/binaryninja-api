#pragma once
#include <string>
#include <vector>
#include <optional>

#include "refcount.hpp"
#include "secretsprovider.h"

namespace BinaryNinja {

	/*!
	    Class for storing secrets (e.g. tokens) in a system-specific manner
	 */
	class SecretsProvider : public StaticCoreRefCountObject<BNSecretsProvider>
	{
		std::string m_nameForRegister;

	  protected:
		SecretsProvider(const std::string& name);
		SecretsProvider(BNSecretsProvider* provider);

		static bool HasDataCallback(void* ctxt, const char* key);
		static char* GetDataCallback(void* ctxt, const char* key);
		static bool StoreDataCallback(void* ctxt, const char* key, const char* data);
		static bool DeleteDataCallback(void* ctxt, const char* key);

	  public:
		/*!
		    Check if data for a specific key exists, but do not retrieve it
		    \param key Key for data
		    \return True if data exists
		 */
		virtual bool HasData(const std::string& key) = 0;
		/*!
		    Retrieve data for the given key, if it exists
		    \param key Key for data
		    \return Optional with data, if it exists, or empty optional if it does not exist
		            or otherwise could not be retrieved.
		 */
		virtual std::optional<std::string> GetData(const std::string& key) = 0;
		/*!
		    Store data with the given key
		    \param key Key for data
		    \param data Data to store
		    \return True if the data was stored
		 */
		virtual bool StoreData(const std::string& key, const std::string& data) = 0;
		/*!
		    Delete stored data with the given key
		    \param key Key for data
		    \return True if it was deleted
		 */
		virtual bool DeleteData(const std::string& key) = 0;

		/*!
		    Retrieve the list of providers
		    \return A list of registered providers
		 */
		static std::vector<Ref<SecretsProvider>> GetList();
		/*!
		    Retrieve a provider by name
		    \param name Name of provider
		    \return Provider object, if one with the given name is regestered, or nullptr if not
		 */
		static Ref<SecretsProvider> GetByName(const std::string& name);
		/*!
		    Register a new provider
		    \param provider New provider to register
		 */
		static void Register(SecretsProvider* provider);
	};

	class CoreSecretsProvider : public SecretsProvider
	{
	  public:
		CoreSecretsProvider(BNSecretsProvider* provider);

		virtual bool HasData(const std::string& key) override;
		virtual std::optional<std::string> GetData(const std::string& key) override;
		virtual bool StoreData(const std::string& key, const std::string& data) override;
		virtual bool DeleteData(const std::string& key) override;
	};
}