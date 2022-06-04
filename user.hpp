#pragma once
#include <string>
#include "refcount.hpp"
#include "user.h"
namespace BinaryNinja {
	class User : public CoreRefCountObject<BNUser, BNNewUserReference, BNFreeUser>
	{
	  private:
		std::string m_id;
		std::string m_name;
		std::string m_email;

	  public:
		User(BNUser* user);
		std::string GetName();
		std::string GetEmail();
		std::string GetId();
	};
}