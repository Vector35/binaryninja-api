#pragma once
#include "core/binaryninja_defs.h"

extern "C" {
	enum BNTagTypeType
	{
		UserTagType,
		NotificationTagType,
		BookmarksTagType
	};

	enum BNTagReferenceType
	{
		AddressTagReference,
		FunctionTagReference,
		DataTagReference
	};

	struct BNTag;
	struct BNTagType;
	struct BNArchitecture;
	struct BNFunction;
	struct BNBinaryView;

	struct BNTagReference
	{
		BNTagReferenceType refType;
		bool autoDefined;
		BNTag* tag;
		BNArchitecture* arch;
		BNFunction* func;
		uint64_t addr;
	};

	BINARYNINJACOREAPI BNTagType* BNCreateTagType(BNBinaryView* view);
	BINARYNINJACOREAPI BNTagType* BNNewTagTypeReference(BNTagType* tagType);
	BINARYNINJACOREAPI void BNFreeTagType(BNTagType* tagType);
	BINARYNINJACOREAPI void BNFreeTagTypeList(BNTagType** tagTypes, size_t count);
	BINARYNINJACOREAPI BNBinaryView* BNTagTypeGetView(BNTagType* tagType);
	BINARYNINJACOREAPI char* BNTagTypeGetId(BNTagType* tagType);
	BINARYNINJACOREAPI char* BNTagTypeGetName(BNTagType* tagType);
	BINARYNINJACOREAPI void BNTagTypeSetName(BNTagType* tagType, const char* name);
	BINARYNINJACOREAPI char* BNTagTypeGetIcon(BNTagType* tagType);
	BINARYNINJACOREAPI void BNTagTypeSetIcon(BNTagType* tagType, const char* icon);
	BINARYNINJACOREAPI bool BNTagTypeGetVisible(BNTagType* tagType);
	BINARYNINJACOREAPI void BNTagTypeSetVisible(BNTagType* tagType, bool visible);
	BINARYNINJACOREAPI BNTagTypeType BNTagTypeGetType(BNTagType* tagType);
	BINARYNINJACOREAPI void BNTagTypeSetType(BNTagType* tagType, BNTagTypeType type);

	BINARYNINJACOREAPI BNTag* BNCreateTag(BNTagType* type, const char* data);
	BINARYNINJACOREAPI BNTag* BNNewTagReference(BNTag* tag);
	BINARYNINJACOREAPI void BNFreeTag(BNTag* tag);
	BINARYNINJACOREAPI void BNFreeTagList(BNTag** tags, size_t count);
	BINARYNINJACOREAPI char* BNTagGetId(BNTag* tag);
	BINARYNINJACOREAPI BNTagType* BNTagGetType(BNTag* tag);
	BINARYNINJACOREAPI char* BNTagGetData(BNTag* tag);
	BINARYNINJACOREAPI void BNTagSetData(BNTag* tag, const char* data);

	BINARYNINJACOREAPI void BNAddTagType(BNBinaryView* view, BNTagType* tagType);
	BINARYNINJACOREAPI void BNRemoveTagType(BNBinaryView* view, BNTagType* tagType);
	BINARYNINJACOREAPI BNTagType* BNGetTagType(BNBinaryView* view, const char* name);
	BINARYNINJACOREAPI BNTagType* BNGetTagTypeWithType(BNBinaryView* view, const char* name, BNTagTypeType type);
	BINARYNINJACOREAPI BNTagType* BNGetTagTypeById(BNBinaryView* view, const char* id);
	BINARYNINJACOREAPI BNTagType* BNGetTagTypeByIdWithType(BNBinaryView* view, const char* id, BNTagTypeType type);
	BINARYNINJACOREAPI BNTagType** BNGetTagTypes(BNBinaryView* view, size_t* count);

	BINARYNINJACOREAPI void BNAddTag(BNBinaryView* view, BNTag* tag, bool user);
	BINARYNINJACOREAPI BNTag* BNGetTag(BNBinaryView* view, const char* tagId);
	BINARYNINJACOREAPI void BNRemoveTag(BNBinaryView* view, BNTag* tag, bool user);

	BINARYNINJACOREAPI BNTagReference* BNGetAllTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAllAddressTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAllFunctionTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAllTagReferencesOfType(
	    BNBinaryView* view, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetTagReferencesOfType(BNBinaryView* view, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetDataTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAutoDataTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetUserDataTagReferences(BNBinaryView* view, size_t* count);
	BINARYNINJACOREAPI void BNRemoveTagReference(BNBinaryView* view, BNTagReference ref);
	BINARYNINJACOREAPI void BNFreeTagReferences(BNTagReference* refs, size_t count);
	BINARYNINJACOREAPI BNTag** BNGetDataTags(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoDataTags(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserDataTags(BNBinaryView* view, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetDataTagsOfType(
	    BNBinaryView* view, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoDataTagsOfType(
	    BNBinaryView* view, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserDataTagsOfType(
	    BNBinaryView* view, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetDataTagsInRange(
	    BNBinaryView* view, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAutoDataTagsInRange(
	    BNBinaryView* view, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetUserDataTagsInRange(
	    BNBinaryView* view, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI void BNAddAutoDataTag(BNBinaryView* view, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoDataTag(BNBinaryView* view, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoDataTagsOfType(BNBinaryView* view, uint64_t addr, BNTagType* tagType);
	BINARYNINJACOREAPI void BNAddUserDataTag(BNBinaryView* view, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserDataTag(BNBinaryView* view, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserDataTagsOfType(BNBinaryView* view, uint64_t addr, BNTagType* tagType);

	BINARYNINJACOREAPI size_t BNGetTagReferencesOfTypeCount(BNBinaryView* view, BNTagType* tagType);
	BINARYNINJACOREAPI size_t BNGetAllTagReferencesOfTypeCount(BNBinaryView* view, BNTagType* tagType);
	BINARYNINJACOREAPI void BNGetAllTagReferenceTypeCounts(
	    BNBinaryView* view, BNTagType*** tagTypes, size_t** counts, size_t* count);
	BINARYNINJACOREAPI void BNFreeTagReferenceTypeCounts(BNTagType** tagTypes, size_t* counts);

	BINARYNINJACOREAPI BNTagReference* BNGetFunctionAllTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetFunctionTagReferencesOfType(
	    BNFunction* func, BNTagType* tagType, size_t* count);

	BINARYNINJACOREAPI BNTagReference* BNGetAddressTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAutoAddressTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetUserAddressTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAddressTags(BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoAddressTags(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserAddressTags(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAddressTagsOfType(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoAddressTagsOfType(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserAddressTagsOfType(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAddressTagsInRange(
	    BNFunction* func, BNArchitecture* arch, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAutoAddressTagsInRange(
	    BNFunction* func, BNArchitecture* arch, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetUserAddressTagsInRange(
	    BNFunction* func, BNArchitecture* arch, uint64_t start, uint64_t end, size_t* count);
	BINARYNINJACOREAPI void BNAddAutoAddressTag(BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoAddressTag(BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoAddressTagsOfType(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTagType* tagType);
	BINARYNINJACOREAPI void BNAddUserAddressTag(BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserAddressTag(BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserAddressTagsOfType(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTagType* tagType);

	BINARYNINJACOREAPI BNTagReference* BNGetFunctionTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetAutoFunctionTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTagReference* BNGetUserFunctionTagReferences(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetFunctionTags(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoFunctionTags(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserFunctionTags(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetFunctionTagsOfType(BNFunction* func, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetAutoFunctionTagsOfType(BNFunction* func, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI BNTag** BNGetUserFunctionTagsOfType(BNFunction* func, BNTagType* tagType, size_t* count);
	BINARYNINJACOREAPI void BNAddAutoFunctionTag(BNFunction* func, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoFunctionTag(BNFunction* func, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveAutoFunctionTagsOfType(BNFunction* func, BNTagType* tagType);
	BINARYNINJACOREAPI void BNAddUserFunctionTag(BNFunction* func, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserFunctionTag(BNFunction* func, BNTag* tag);
	BINARYNINJACOREAPI void BNRemoveUserFunctionTagsOfType(BNFunction* func, BNTagType* tagType);
}