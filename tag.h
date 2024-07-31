#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <string>
#include <vector>

namespace BinaryNinja
{
	class BinaryView;

	/*!
		\ingroup binaryview
	*/
	class TagType : public CoreRefCountObject<BNTagType, BNNewTagTypeReference, BNFreeTagType>
	{
	  public:
		typedef BNTagTypeType Type;

		TagType(BNTagType* tagType);
		TagType(BinaryView* view);
		TagType(BinaryView* view, const std::string& name, const std::string& icon, bool visible = true,
		    Type type = UserTagType);

		/*!
			\return BinaryView for this TagType
		*/
		BinaryView* GetView() const;

		/*!
		    \return Unique ID of the TagType
		*/
		std::string GetId() const;

		/*!
		    \return Name of the TagType
		*/
		std::string GetName() const;

		/*!
		    Set the name of the TagType

		    \param name New name
		*/
		void SetName(const std::string& name);

		/*!
		    \return Unicode string containing an emoji to be used as an icon
		*/
		std::string GetIcon() const;

		/*!
		    Set the icon to be used for a TagType

		    \param icon Unicode string containing an emoji to be used as an icon
		*/
		void SetIcon(const std::string& icon);

		/*!
		    \return Whether the tags of this type are visible
		*/
		bool GetVisible() const;

		/*!
		    Set whether the tags of this type are visible

		    \param visible Whether the tags of this type are visible
		*/
		void SetVisible(bool visible);

		/*!
			One of: UserTagType, NotificationTagType, BookmarksTagType

			\return Tag Type.
		*/
		Type GetType() const;

		/*!
		    \param type Tag Type. One of: UserTagType, NotificationTagType, BookmarksTagType
		*/
		void SetType(Type type);
	};

	class Tag : public CoreRefCountObject<BNTag, BNNewTagReference, BNFreeTag>
	{
	  public:
		Tag(BNTag* tag);
		Tag(Ref<TagType> type, const std::string& data = "");

		/*!
		    \return Unique ID of the Tag
		*/
		std::string GetId() const;

		/*!
		    \return TagType of this tag
		*/
		Ref<TagType> GetType() const;
		std::string GetData() const;
		void SetData(const std::string& data);

		static BNTag** CreateTagList(const std::vector<Ref<Tag>>& tags, size_t* count);
		static std::vector<Ref<Tag>> ConvertTagList(BNTag** tags, size_t count);
		static void FreeTagList(BNTag** tags, size_t count);
		static std::vector<Ref<Tag>> ConvertAndFreeTagList(BNTag** tags, size_t count);
	};

	class Architecture;
	class Function;

	/*!
		\ingroup binaryview
	*/
	struct TagReference
	{
		typedef BNTagReferenceType RefType;

		RefType refType;
		bool autoDefined;
		Ref<Tag> tag;
		Ref<Architecture> arch;
		Ref<Function> func;
		uint64_t addr;

		TagReference();
		TagReference(const BNTagReference& ref);

		bool operator==(const TagReference& other) const;
		bool operator!=(const TagReference& other) const;

		operator BNTagReference() const;

		static BNTagReference* CreateTagReferenceList(const std::vector<TagReference>& tags, size_t* count);
		static std::vector<TagReference> ConvertTagReferenceList(BNTagReference* tags, size_t count);
		static void FreeTagReferenceList(BNTagReference* tags, size_t count);
		static std::vector<TagReference> ConvertAndFreeTagReferenceList(BNTagReference* tags, size_t count);
	};

}
