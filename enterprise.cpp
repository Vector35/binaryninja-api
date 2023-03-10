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
#include <time.h>

using namespace BinaryNinja::Enterprise;

bool BinaryNinja::Enterprise::AuthenticateWithCredentials(const std::string& username, const std::string& password, bool remember)
{
	return BNAuthenticateEnterpriseServerWithCredentials(username.c_str(), password.c_str(), remember);
}


bool BinaryNinja::Enterprise::AuthenticateWithMethod(const std::string& method, bool remember)
{
	return BNAuthenticateEnterpriseServerWithMethod(method.c_str(), remember);
}


std::vector<std::pair<std::string, std::string>> BinaryNinja::Enterprise::GetAuthenticationMethods()
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


bool BinaryNinja::Enterprise::Deauthenticate()
{
	return BNDeauthenticateEnterpriseServer();
}


void BinaryNinja::Enterprise::CancelAuthentication()
{
	return BNCancelEnterpriseServerAuthentication();
}


bool BinaryNinja::Enterprise::Connect()
{
	return BNConnectEnterpriseServer();
}


bool BinaryNinja::Enterprise::UpdateLicense(uint64_t timeout)
{
	return BNUpdateEnterpriseServerLicense(timeout);
}


bool BinaryNinja::Enterprise::ReleaseLicense()
{
	return BNReleaseEnterpriseServerLicense();
}


bool BinaryNinja::Enterprise::IsConnected()
{
	return BNIsEnterpriseServerConnected();
}


bool BinaryNinja::Enterprise::IsAuthenticated()
{
	return BNIsEnterpriseServerAuthenticated();
}


std::string BinaryNinja::Enterprise::GetUsername()
{
	char* value = BNGetEnterpriseServerUsername();
	std::string result = value;
	BNFreeString(value);
	return result;
}


std::string BinaryNinja::Enterprise::GetToken()
{
	char* value = BNGetEnterpriseServerToken();
	std::string result = value;
	BNFreeString(value);
	return result;
}


std::string BinaryNinja::Enterprise::GetServerName()
{
	char* value = BNGetEnterpriseServerName();
	std::string result = value;
	BNFreeString(value);
	return result;
}


std::string BinaryNinja::Enterprise::GetServerId()
{
	char* value = BNGetEnterpriseServerId();
	std::string result = value;
	BNFreeString(value);
	return result;
}


uint64_t BinaryNinja::Enterprise::GetServerVersion()
{
	return BNGetEnterpriseServerVersion();
}


std::string BinaryNinja::Enterprise::GetServerBuildId()
{
	char* value = BNGetEnterpriseServerBuildId();
	std::string result = value;
	BNFreeString(value);
	return result;
}


uint64_t BinaryNinja::Enterprise::GetLicenseExpirationTime()
{
	return BNGetEnterpriseServerLicenseExpirationTime();
}


uint64_t BinaryNinja::Enterprise::GetLicenseDuration()
{
	return BNGetEnterpriseServerLicenseDuration();
}


bool BinaryNinja::Enterprise::IsFloatingLicense()
{
	return BNIsEnterpriseServerFloatingLicense();
}


uint64_t BinaryNinja::Enterprise::GetReservationTimeLimit()
{
	return BNGetEnterpriseServerReservationTimeLimit();
}


bool BinaryNinja::Enterprise::IsLicenseStillActivated()
{
	return BNIsEnterpriseServerLicenseStillActivated();
}


std::string BinaryNinja::Enterprise::GetLastError()
{
	return BNGetEnterpriseServerLastError();
	char* str = BNGetEnterpriseServerLastError();
	std::string value = str;
	BNFreeString(str);
	return value;
}


void BinaryNinja::Enterprise::RegisterNotification(BNEnterpriseServerCallbacks* notify)
{
	BNRegisterEnterpriseServerNotification(notify);
}


void BinaryNinja::Enterprise::UnregisterNotification(BNEnterpriseServerCallbacks* notify)
{
	BNUnregisterEnterpriseServerNotification(notify);
}


BinaryNinja::Enterprise::LicenseCheckout::LicenseCheckout(int64_t duration)
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
	if (!IsLicenseStillActivated() || (!IsFloatingLicense() && (time_t)BNGetLicenseExpirationTime() < time(nullptr)))
	{
		if (!Enterprise::UpdateLicense(duration))
		{
			throw EnterpriseException("Could not checkout a license: " + GetLastError());
		}
		m_acquiredLicense = true;
	}
}


BinaryNinja::Enterprise::LicenseCheckout::~LicenseCheckout()
{
	// UI builds have their own license manager
	if (BNIsUIEnabled())
		return;

	// Don't release if we got one from keychain
	if (m_acquiredLicense)
	{
		Enterprise::ReleaseLicense();
	}
}
