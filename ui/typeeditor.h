
#pragma once

#include "tokenizedtextwidget.h"
#include "uitypes.h"

class BINARYNINJAUIAPI TypeEditor: public TokenizedTextWidget
{
public:
	struct SavedCursorPosition
	{
		struct PositionData
		{
			BinaryNinja::QualifiedName typeName;
			TokenizedTextWidgetCursorPosition position;
			size_t structOffset;
			std::pair<size_t, size_t> lineStart;
		};
		bool restoreCursor;
		bool restoreTop;
		TokenizedTextWidgetSelectionStyle style;
		PositionData cursor;
		PositionData base;
		PositionData top;
	};

private:
	Q_OBJECT

	PlatformRef m_platform;
	std::optional<BinaryNinja::TypeContainer> m_typeContainer;
	std::optional<BinaryViewRef> m_binaryView;
	// Empty view for bv-requiring operations
	mutable std::optional<BinaryViewRef> m_emptyView;
	std::vector<BinaryNinja::QualifiedName> m_typeNames;

	// line index -> index of first line from wrapped line
	std::vector<size_t> m_lineUnwrapIndex;
	// line index -> type name
	std::vector<BinaryNinja::QualifiedName> m_lineTypeRefs;
	// type name -> index of first line
	std::map<BinaryNinja::QualifiedName, size_t> m_lineTypeStarts;
	// type name -> { offset -> index of first { line, token } at offset }
	std::map<BinaryNinja::QualifiedName, std::map<size_t, std::pair<size_t, size_t>>> m_lineTypeOffsetStarts;
	// type name -> { offset -> index of last { line, token } at offset }
	std::map<BinaryNinja::QualifiedName, std::map<size_t, std::pair<size_t, size_t>>> m_lineTypeOffsetEnds;
	// line index -> line
	std::vector<BinaryNinja::TypeDefinitionLine> m_typeLines;

	TokenizedTextWidgetCursorPosition m_originalBase;

	bool m_wrapLines;
	bool m_showInherited;

public:
	TypeEditor(QWidget* parent);

	static void registerActions();
	void bindActions();

	PlatformRef platform() const { return m_platform; }
	void setPlatform(PlatformRef platform) { m_platform = platform; }

	std::optional<BinaryViewRef> binaryView() const { return m_binaryView; }
	void setBinaryView(std::optional<BinaryViewRef> binaryView) { m_binaryView = binaryView; }

	std::optional<std::reference_wrapper<const BinaryNinja::TypeContainer>> typeContainer() const;
	void setTypeContainer(std::optional<BinaryNinja::TypeContainer> container);

	std::vector<BinaryNinja::QualifiedName> typeNames() const { return m_typeNames; }
	void setTypeNames(const std::vector<BinaryNinja::QualifiedName>& names);

	int selectedLineCount() const;
	std::unordered_set<size_t> selectedLineStarts() const;
	int selectedRootTypeCount() const;
	std::unordered_set<BinaryNinja::QualifiedName> selectedRootTypes() const;
	std::optional<size_t> firstWrappedLineIndexForLineIndex(size_t lineIndex) const;
	std::optional<size_t> lastWrappedLineIndexForLineIndex(size_t lineIndex) const;
	std::optional<std::reference_wrapper<const BinaryNinja::TypeDefinitionLine>> typeLineAtIndex(size_t lineIndex) const;
	std::optional<std::reference_wrapper<const BinaryNinja::TypeDefinitionLine>> typeLineAtPosition(const TokenizedTextWidgetCursorPosition& position) const;
	std::optional<BinaryNinja::QualifiedName> rootTypeNameAtIndex(size_t lineIndex) const;
	std::optional<BinaryNinja::QualifiedName> rootTypeNameAtPosition(const TokenizedTextWidgetCursorPosition& position) const;
	std::optional<TypeRef> rootTypeAtIndex(size_t lineIndex) const;
	std::optional<TypeRef> rootTypeAtPosition(const TokenizedTextWidgetCursorPosition& position) const;
	std::optional<uint64_t> offsetAtIndex(size_t lineIndex) const;
	std::optional<uint64_t> offsetAtPosition(const TokenizedTextWidgetCursorPosition& position) const;
	std::optional<int64_t> relativeOffsetAtPosition(const TokenizedTextWidgetCursorPosition& position) const;
	std::optional<TokenizedTextWidgetCursorPosition> firstPositionForOffset(const BinaryNinja::QualifiedName& name, uint64_t offset) const;
	std::optional<TokenizedTextWidgetCursorPosition> lastPositionForOffset(const BinaryNinja::QualifiedName& name, uint64_t offset) const;
	void selectOffsetRange(const BinaryNinja::QualifiedName& name, uint64_t start, uint64_t end);

	SavedCursorPosition saveCursorPosition() const;
	void restoreCursorPosition(const SavedCursorPosition& position);

	bool canCreateAllMembersForStructure();
	void createAllMembersForStructure();
	bool canCreateCurrentMemberForStructure();
	void createCurrentMemberForStructure();
	bool canRename();
	void rename();
	void renameRoot();
	void renameMember();
	bool canUndefine();
	void undefine();
	void undefineRoots();
	void undefineMembers();
	bool canAppendField();
	void appendField();
	bool canCreateArray();
	void createArray();
	bool canChangeType();
	void changeType();
	void changeTypeRoot();
	void changeTypeAddMember(bool atEnd = false);
	void changeTypeMember();
	bool canChangeTypeMembers();
	void changeTypeMembers(TypeRef newType);
	bool canSetStructureSize();
	void setStructureSize();
	bool canAddUserXref();
	void addUserXref();
	bool canMakePointer();
	void makePointer();
	bool canMakeCString();
	void makeCString();
	bool canMakeUTF16String();
	void makeUTF16String();
	bool canMakeUTF32String();
	void makeUTF32String();
	bool canCycleIntegerSize();
	void cycleIntegerSize();
	bool canCycleFloatSize();
	void cycleFloatSize();
	bool canInvertIntegerSize();
	void invertIntegerSize();
	bool canMakeInt8();
	void makeInt8();
	bool canMakeInt16();
	void makeInt16();
	bool canMakeInt32();
	void makeInt32();
	bool canMakeInt64();
	void makeInt64();
	bool canMakeFloat32();
	void makeFloat32();
	bool canMakeFloat64();
	void makeFloat64();
	bool canGoToAddress(bool selecting);
	void goToAddress(bool selecting);
	void toggleWrapLines();
	void toggleShowInherited();

	std::string getDebugText();

Q_SIGNALS:
	void typeNameNavigated(const std::string& typeName);
	void currentTypeUpdated(const BinaryNinja::QualifiedName& typeName);
	void currentTypeDeleted(const BinaryNinja::QualifiedName& typeName);
	void currentTypeNameUpdated(const BinaryNinja::QualifiedName& typeName);

private:
	void updateLines();
	BinaryViewRef binaryViewOrEmpty() const;
	void updateInTransaction(std::function<void()> transaction);
	void updateInTransaction(std::function<void(BinaryViewRef)> transaction);
	std::string dumpType(TypeRef type);

	void forEachMember(const TokenizedTextWidgetCursorPosition& begin, const TokenizedTextWidgetCursorPosition& end,
		std::function<void(TypeRef /* type */, TypeRef /* parent */, size_t /* memberIndex */, size_t /* rootOffset */)> func, bool childrenFirst = false);
};
