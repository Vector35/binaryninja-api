#pragma once
#include "tag.h"

namespace BinaryNinja {
	class BinaryView;

	class TagType : public CoreRefCountObject<BNTagType, BNNewTagTypeReference, BNFreeTagType>
	{
	  public:
		typedef BNTagTypeType Type;

		TagType(BNTagType* tagType);
		TagType(BinaryView* view);
		TagType(BinaryView* view, const std::string& name, const std::string& icon, bool visible = true,
		    Type type = UserTagType);

		BinaryView* GetView() const;
		std::string GetId() const;
		std::string GetName() const;
		void SetName(const std::string& name);
		std::string GetIcon() const;
		void SetIcon(const std::string& icon);
		bool GetVisible() const;
		void SetVisible(bool visible);
		Type GetType() const;
		void SetType(Type type);
	};

	class Tag : public CoreRefCountObject<BNTag, BNNewTagReference, BNFreeTag>
	{
	  public:
		Tag(BNTag* tag);
		Tag(Ref<TagType> type, const std::string& data = "");

		std::string GetId() const;
		Ref<TagType> GetType() const;
		std::string GetData() const;
		void SetData(const std::string& data);
		void AddToView(Ref<BinaryView> view);

		static BNTag** CreateTagList(const std::vector<Ref<Tag>>& tags, size_t* count);
		static std::vector<Ref<Tag>> ConvertTagList(BNTag** tags, size_t count);
		static std::vector<Ref<Tag>> ConvertAndFreeTagList(BNTag** tags, size_t count);
		static Ref<TagType> GetTagTypeByNameFromView(Ref<BinaryView> view, const std::string& name);
	};

	class Architecture;
	class Function;
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
		static std::vector<TagReference> ConvertAndFreeTagReferenceList(BNTagReference* tags, size_t count);
	};
}