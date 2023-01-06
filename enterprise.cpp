// Copyright (c) 2015-2023 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "enterprise.h"

using namespace BinaryNinja::EnterpriseServer;

bool BinaryNinja::EnterpriseServer::AuthenticateWithCredentials(const std::string& username, const std::string& password, bool remember)
{
	return BNAuthenticateEnterpriseServerWithCredentials(username.c_str(), password.c_str(), remember);
}


bool BinaryNinja::EnterpriseServer::AuthenticateWithMethod(const std::string& method, bool remember)
{
	return BNAuthenticateEnterpriseServerWithMethod(method.c_str(), remember);
}


std::vector<std::pair<std::string, std::string>> BinaryNinja::EnterpriseServer::GetAuthenticationMethods()
{
	char** methods;
	char** names;
	size_t count = BNGetEnterpriseServerAuthenticationMethods(&methods, &names);

	std::vector<std::pair<std::string, std::string>> results;
	for (size_t i = 0; i < count; i++)
	{
		results.push_back({methods[i], names[i]});
	}

	BNFreeStringList(methods, count);
	BNFreeStringList(names, count);

	return results;
}


bool BinaryNinja::EnterpriseServer::Deauthenticate()
{
	return BNDeauthenticateEnterpriseServer();
}


void BinaryNinja::EnterpriseServer::CancelAuthentication()
{
	return BNCancelEnterpriseServerAuthentication();
}


bool BinaryNinja::EnterpriseServer::Connect()
{
	return BNConnectEnterpriseServer();
}


bool BinaryNinja::EnterpriseServer::AcquireLicense(uint64_t timeout)
{
	return BNAcquireEnterpriseServerLicense(timeout);
}


bool BinaryNinja::EnterpriseServer::ReleaseLicense()
{
	return BNReleaseEnterpriseServerLicense();
}


bool BinaryNinja::EnterpriseServer::IsConnected()
{
	return BNIsEnterpriseServerConnected();
}


bool BinaryNinja::EnterpriseServer::IsAuthenticated()
{
	return BNIsEnterpriseServerAuthenticated();
}


std::string BinaryNinja::EnterpriseServer::GetUsername()
{
	char* value = BNGetEnterpriseServerUsername();
	std::string result = value;
	BNFreeString(value);
	return result;
}


std::string BinaryNinja::EnterpriseServer::GetToken()
{
	char* value = BNGetEnterpriseServerToken();
	std::string result = value;
	BNFreeString(value);
	return result;
}


std::string BinaryNinja::EnterpriseServer::GetServerName()
{
	char* value = BNGetEnterpriseServerName();
	std::string result = value;
	BNFreeString(value);
	return result;
}


std::string BinaryNinja::EnterpriseServer::GetServerId()
{
	char* value = BNGetEnterpriseServerId();
	std::string result = value;
	BNFreeString(value);
	return result;
}


uint64_t BinaryNinja::EnterpriseServer::GetServerVersion()
{
	return BNGetEnterpriseServerVersion();
}


std::string BinaryNinja::EnterpriseServer::GetServerBuildId()
{
	char* value = BNGetEnterpriseServerBuildId();
	std::string result = value;
	BNFreeString(value);
	return result;
}


uint64_t BinaryNinja::EnterpriseServer::GetLicenseExpirationTime()
{
	return BNGetEnterpriseServerLicenseExpirationTime();
}


uint64_t BinaryNinja::EnterpriseServer::GetLicenseDuration()
{
	return BNGetEnterpriseServerLicenseDuration();
}


bool BinaryNinja::EnterpriseServer::IsFloatingLicense()
{
	return BNIsEnterpriseServerFloatingLicense();
}


uint64_t BinaryNinja::EnterpriseServer::GetReservationTimeLimit()
{
	return BNGetEnterpriseServerReservationTimeLimit();
}


bool BinaryNinja::EnterpriseServer::IsLicenseStillActivated()
{
	return BNIsEnterpriseServerLicenseStillActivated();
}


std::string BinaryNinja::EnterpriseServer::GetLastError()
{
	return BNGetEnterpriseServerLastError();
	char* str = BNGetEnterpriseServerLastError();
	std::string value = str;
	BNFreeString(str);
	return value;
}


void BinaryNinja::EnterpriseServer::RegisterNotification(BNEnterpriseServerCallbacks* notify)
{
	BNRegisterEnterpriseServerNotification(notify);
}


void BinaryNinja::EnterpriseServer::UnregisterNotification(BNEnterpriseServerCallbacks* notify)
{
	BNUnregisterEnterpriseServerNotification(notify);
}


BinaryNinja::EnterpriseServer::LicenseCheckout::LicenseCheckout(int64_t duration)
{
	// This is a port of python's binaryninja.enterprise.LicenseCheckout

	// UI builds have their own license manager
	if (BNIsUIEnabled())
		return;

	if (!IsConnected())
	{
		Connect();
	}
	if (!IsAuthenticated())
	{
		// Try keychain
		bool gotAuth = AuthenticateWithMethod("Keychain", false);
		if (!gotAuth)
		{
			char* username = getenv("BN_ENTERPRISE_USERNAME");
			char* password = getenv("BN_ENTERPRISE_PASSWORD");
			if (username && password)
			{
				gotAuth = AuthenticateWithCredentials(username, password, true);
			}
		}
		if (!gotAuth)
		{
			throw EnterpriseException(
				"Could not checkout a license: Not authenticated. Try one of the following: \n"
				" - Log in and check out a license for an extended time\n"
				" - Set BN_ENTERPRISE_USERNAME and BN_ENTERPRISE_PASSWORD environment variables\n"
				" - Use BinaryNinja::Enterprise::AuthenticateWithCredentials or AuthenticateWithMethod in your code"
			);
		}
	}

	// Keychain auth can activate a license if we have one in the keychain
	// If we have an expired named license, try to get a fresh floating one
	if (!IsLicenseStillActivated() || (!IsFloatingLicense() && BNGetLicenseExpirationTime() < time(nullptr)))
	{
		if (!EnterpriseServer::AcquireLicense(duration))
		{
			throw EnterpriseException("Could not checkout a license: " + GetLastError());
		}
		m_acquiredLicense = true;
	}
}


BinaryNinja::EnterpriseServer::LicenseCheckout::~LicenseCheckout()
{
	// UI builds have their own license manager
	if (BNIsUIEnabled())
		return;

	// Don't release if we got one from keychain
	if (m_acquiredLicense)
	{
		EnterpriseServer::ReleaseLicense();
	}
}
