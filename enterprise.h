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

#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include "binaryninjacore.h"

namespace BinaryNinja
{
	/*!
	    API for interacting with an Enterprise Server.
	    These methods will only do anything on Enterprise editions of Binary Ninja.
	 */
	namespace Enterprise
	{
		/*!
		    Custom exception class for all Enterprise functions that can throw exceptions
		 */
		struct EnterpriseException: std::runtime_error {
			EnterpriseException(const std::string& what): std::runtime_error(what) {}
		};

		/*!
		    Authenticate to the server with username and password
		    \param username Username to authenticate with
		    \param password Password to authenticate with
		    \param remember Remember token in keychain
		    \return True if successful
		 */
		bool AuthenticateWithCredentials(const std::string& username, const std::string& password, bool remember);

		/*!
		    Authenticate with an external provider
		    \param method Provider method
		    \param remember Remember token in keychain
		    \return True if successful
		 */
		bool AuthenticateWithMethod(const std::string& method, bool remember);

		/*!
		    Get a list of accepted methods for authentication
		    \return List of (method, name) pairs
		 */
		std::vector<std::pair<std::string, std::string>> GetAuthenticationMethods();

		/*!
		    Forget saved credentials
		    \return True if successful
		 */
		bool Deauthenticate();

		/*!
		    Cancel a currently running authentication task
		 */
		void CancelAuthentication();

		/*!
		    Perform initial connect to the server, pulling signing key and time limit
		    \return True if successful
		 */
		bool Connect();

		/*!
		    Acquire or refresh a floating license
		    \param timeout Time (in minutes)
		    \return True if successful
		 */
		bool UpdateLicense(uint64_t timeout);

		/*!
		    Release the current hold on a license
		    \return True if successful
		 */
		bool ReleaseLicense();

		/*!
		    Check if the server is connected
		    \return True if connected
		 */
		bool IsConnected();

		/*!
		    Check if the user has authenticated with the server
		    \return True if authenticated
		 */
		bool IsAuthenticated();

		/*!
		    Get currently connected username
		    \return Username of currently connected user
		 */
		std::string GetUsername();

		/*!
		    Get token for current login session
		    \return Token for currently connected user
		 */
		std::string GetToken();

		/*!
		    Get the display name of the currently connected server
		    \return Display name of the currently connected server
		 */
		std::string GetServerName();

		/*!
		    Get the internal id of the currently connected server
		    \return Id of the currently connected server
		 */
		std::string GetServerId();

		/*!
		    Get the version number of the currently connected server
		    \return Version of the currently connected server
		 */
		uint64_t GetServerVersion();

		/*!
		    Get the build id string of the currently connected server
		    \return Build id of the currently connected server
		 */
		std::string GetServerBuildId();

		/*!
		    Get the expiry time for the current license
		    \return Expiry time, in seconds from the epoch
		 */
		uint64_t GetLicenseExpirationTime();

		/*!
		    Get the total length of the current license
		    \return Total time, in seconds
		 */
		uint64_t GetLicenseDuration();

		/*!
		    Determine if a floating license is currently active
		    \return True if a floating license is active
		 */
		bool IsFloatingLicense();

		/*!
		    Get the maximum time limit for reservations
		    \return Maximum reservation time, in seconds
		 */
		uint64_t GetReservationTimeLimit();

		/*!
		    Check if the user's license is still activated
		    \return True if still activated
		 */
		bool IsLicenseStillActivated();

		/*!
		    Get the last recorded error
		    \return Error text
		 */
		std::string GetLastError();

		/*!
			Register an object to receive callbacks when enterprise server events happen
			\param notify Object to receive callbacks
		 */
		void RegisterNotification(BNEnterpriseServerCallbacks* notify);

		/*!
			Un-register a previously registered notification handler object
			\param notify Object to un-register
		 */
		void UnregisterNotification(BNEnterpriseServerCallbacks* notify);

		/*!
		    RAII object for holding an Enterprise license in a scope. Automatically
		    releases the license when destroyed.

		    \b Example:
		    \code{.cpp}

		    using namespace BinaryNinja;
		    assert(Enterprise::Connect());
		    assert(Enterprise::AuthenticateWithCredentials("username", "password", true));
		    {
		        Enterprise::LicenseCheckout _{};
		        Ref<BinaryView> bv = OpenView("/bin/ls", true, {}, options);
		        printf("%llx\n", bv->GetStart());
		        // License is released at end of scope
		    }

		    \endcode
		 */
		class LicenseCheckout
		{
			bool m_acquiredLicense;
		public:
			/*!
			    RAII constructor that checks out a license. License will be refreshed
			    automatically in a background thread while checked out, in intervals of `duration`
			    In the event of program crash, the license will expire `duration` seconds after
			    the most recent background refresh, so you may want a smaller value like 60 if
			    you expect your program to crash / be killed often.
			    See class docs for example usage.
			    \param duration Duration for refreshes and also length of each license checkout.
			    \throws EnterpriseException If license checkout fails
			 */
			explicit LicenseCheckout(int64_t duration = 900);

			~LicenseCheckout();
		};
	}
}
