#pragma once
#include "binaryninja_defs.h"

extern "C" {
	struct BNUser;
	struct BNFileMetadata;
	// User
	BINARYNINJACOREAPI BNUser* BNNewUserReference(BNUser* user);
	BINARYNINJACOREAPI void BNFreeUser(BNUser* user);
	BINARYNINJACOREAPI BNUser** BNGetUsers(BNFileMetadata* file, size_t* count);
	BINARYNINJACOREAPI void BNFreeUserList(BNUser** users, size_t count);
	BINARYNINJACOREAPI char* BNGetUserName(BNUser* user);
	BINARYNINJACOREAPI char* BNGetUserEmail(BNUser* user);
	BINARYNINJACOREAPI char* BNGetUserId(BNUser* user);
}