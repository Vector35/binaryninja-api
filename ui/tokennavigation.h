#pragma once

#include "uitypes.h"
#include "action.h"
#include "binaryninjaapi.h"

#include <optional>
#include <string>
#include <vector>

class View;
class ViewFrame;

/*!

	\defgroup tokennavigation TokenNavigation
	\ingroup uiapi
*/

/*!
	The kind of behavior that activating a token (by double-clicking it, or by pressing the
	"Activate Selection" key) should perform.

	\ingroup tokennavigation
*/
enum TokenActivationType
{
	/*! Nothing can be done with the selected token */
	NoTokenActivation,
	/*! Navigate to an address in the binary */
	NavigateToAddressActivation,
	/*! Show a named type, optionally scrolling to a member at a given offset */
	NavigateToTypeActivation,
	/*! Navigate to the line that defines a goto label */
	NavigateToGotoLabelActivation,
	/*! Navigate to the brace matching the selected one */
	NavigateToMatchingBraceActivation,
	/*! Rename the selected variable */
	DefineNameActivation,
	/*! Edit the selected comment */
	EditCommentActivation
};

/*!
	The result of resolving a token into the behavior that activating it should perform.

	\ingroup tokennavigation
*/
struct BINARYNINJAUIAPI TokenActivationAction
{
	TokenActivationType type = NoTokenActivation;
	/*! Target address for NavigateToAddressActivation, or the label identifier for
	    NavigateToGotoLabelActivation */
	uint64_t address = 0;
	/*! Name of the type to show for NavigateToTypeActivation */
	std::string typeName;
	/*! Offset of the member to show for NavigateToTypeActivation */
	uint64_t typeOffset = 0;

	bool isValid() const { return type != NoTokenActivation; }
	/*! True for the actions that move the view somewhere, as opposed to those that edit the
	    database. Used to decide whether an entry point that only navigates should act. */
	bool isNavigation() const;
	/*! True for actions that navigate to an address. */
	bool isNavigationToAddress() const;
};

/*!
	Look up the derived string that a token refers to, if any. Only tokens rendered with
	DerivedStringReferenceTokenContext refer to a derived string.

	\ingroup tokennavigation
*/

std::optional<BinaryNinja::DerivedString> BINARYNINJAUIAPI getDerivedStringForToken(
    FunctionRef func, const BinaryNinja::InstructionTextToken& token);

/*!
	Get the address that a string token refers to. For a derived string with a known location,
	this is the location backing the string (which is not where the token itself is rendered).

	\ingroup tokennavigation
*/
uint64_t BINARYNINJAUIAPI getAddressForStringToken(FunctionRef func, const BinaryNinja::InstructionTextToken& token);

/*!
	If the given address is an external symbol that is backed by another file in the project,
	open that file at the corresponding location.

	\ingroup tokennavigation
*/
bool BINARYNINJAUIAPI navigateToExternalLinkForAddress(BinaryViewRef data, uint64_t linkSourceAddr);

/*!
	Find the single token on a line that can be navigated to, for use when no individual token is
	selected. Tokens are searched for in order of preference, and a category containing more than
	one candidate is treated as ambiguous rather than picking one arbitrarily.

	\ingroup tokennavigation
*/
std::optional<uint64_t> BINARYNINJAUIAPI getNavigationTargetForLineTokens(
    const std::vector<BinaryNinja::InstructionTextToken>& tokens);

/*!
	Shared implementation of "activate the selected token", used by every view that renders
	tokens so that double-clicking a token and pressing the "Activate Selection" key behave
	identically everywhere.

	Views inherit from this alongside their widget and View base classes, provide the context
	that token resolution needs, and implement the handful of operations that are view specific.

	\ingroup tokennavigation
*/
class BINARYNINJAUIAPI TokenNavigationHandler
{
public:
	virtual ~TokenNavigationHandler() = default;

	/*! Resolve a token into the action that activating it should perform. Returns an invalid
	    action if the token is not one that can be activated. */
	TokenActivationAction getActionForToken(const HighlightTokenState& highlight);

	/*! Resolve the current selection into an action, falling back to the contents of the
	    current line when no single token is selected. */
	TokenActivationAction getActionForSelection(const HighlightTokenState& highlight);

	/*! Perform the action for the current selection. If navigationOnly is set, actions that
	    edit the database (renaming a variable, editing a comment) are not performed. Returns
	    true if an action was performed. */
	bool activateSelectedToken(const HighlightTokenState& highlight, bool navigationOnly = false);

	/*! Determine whether activateSelectedToken would do anything, for use as the validity
	    check of an action. */
	bool canActivateSelectedToken(const HighlightTokenState& highlight, bool navigationOnly = false);

	/*! Get the target address for the current selection if it is an action that navigates
	    to an address. */
	std::optional<uint64_t> getNavigationAddressForSelectedToken(const HighlightTokenState& highlight);

	/*! Determine whether getNavigationAddressForSelectedToken would return an address to
	    navigate to, for use as the validity check of an action. */
	bool canNavigateToAddressForSelectedToken(const HighlightTokenState& highlight);

protected:
	/*! The binary view that the tokens were rendered from */
	virtual BinaryViewRef getBinaryViewForTokenActivation() = 0;
	/*! The widget for this view */
	virtual QWidget* getWidgetForTokenActivation() = 0;
	/*! The view to navigate */
	virtual View* getViewForTokenActivation() = 0;
	/*! The context that owns the view */
	virtual UIContext* getUIContextForTokenActivation();
	/*! The view frame that owns the view */
	virtual ViewFrame* getViewFrameForTokenActivation();
	/*! The function that the tokens were rendered from, if any. Required to resolve tokens that
	    refer to an IL expression, such as derived strings. */
	virtual FunctionRef getFunctionForTokenActivation() { return nullptr; }
	/*! The tokens of the line containing the selection, used when no single token is selected */
	virtual std::optional<std::vector<BinaryNinja::InstructionTextToken>> getTokensForLineWithSelection()
	{
		return std::nullopt;
	}
	/*! An action to fall back on when neither the selected token nor the tokens on the line
	    resolve to anything, such as navigating to the function that a header line describes */
	virtual TokenActivationAction getActionForLineWithSelection() { return TokenActivationAction(); }

	/*! Navigate to an address within this view, or to wherever the user's preferences say that
	    the address should be shown */
	virtual void navigateToTokenTarget(uint64_t addr) = 0;
	/*! Navigate to the line defining a goto label. Views without goto labels need not implement
	    this. */
	virtual bool navigateToTokenGotoLabel(uint64_t label)
	{
		(void)label;
		return false;
	}
	/*! Navigate to the brace matching the selected one. Views without braces need not implement
	    this. */
	virtual bool navigateToTokenMatchingBrace() { return false; }
	/*! Rename the selected variable */
	virtual void defineNameForSelectedToken() {}
	/*! Edit the selected comment */
	virtual void editCommentForSelectedToken() {}
};
