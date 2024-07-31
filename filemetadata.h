#pragma once

#include "binaryninjacore.h"
#include "refcount.h"
#include <functional>
#include <optional>
#include <string>

namespace BinaryNinja
{
	class BinaryView;
	class Database;
	class KeyValueStore;
	class ProjectFile;
	class SaveSettings;
	class UndoEntry;
	class User;


	/*!
		\ingroup filemetadata
	*/
	class NavigationHandler
	{
	  private:
		BNNavigationHandler m_callbacks;

		static char* GetCurrentViewCallback(void* ctxt);
		static uint64_t GetCurrentOffsetCallback(void* ctxt);
		static bool NavigateCallback(void* ctxt, const char* view, uint64_t offset);

	  public:
		NavigationHandler();
		virtual ~NavigationHandler() {}

		BNNavigationHandler* GetCallbacks() { return &m_callbacks; }

		virtual std::string GetCurrentView() = 0;
		virtual uint64_t GetCurrentOffset() = 0;
		virtual bool Navigate(const std::string& view, uint64_t offset) = 0;
	};


	/*!
		\ingroup filemetadata
	*/
	class FileMetadata : public CoreRefCountObject<BNFileMetadata, BNNewFileReference, BNFreeFileMetadata>
	{
	  public:
		FileMetadata();
		FileMetadata(const std::string& filename);
		FileMetadata(Ref<ProjectFile> projectFile);
		FileMetadata(BNFileMetadata* file);

		/*! Close the underlying file handle
		*/
		void Close();

		void SetNavigationHandler(NavigationHandler* handler);

		/*! Get the original name of the binary opened if a bndb, otherwise the current filename

			\return The original name of the binary opened if a bndb, otherwise returns the current filename
		*/
		std::string GetOriginalFilename() const;

		/*! If the filename is not open in a BNDB, sets the filename for the current file.

			\param name New name
		*/
		void SetOriginalFilename(const std::string& name);

		/*!
			\return The name of the open bndb or binary filename
		*/
		std::string GetFilename() const;

		/*! Set the filename for the current BNDB or binary.

		 	\param name Set the filename for the current BNDB or binary.
		*/
		void SetFilename(const std::string& name);

		/*! Whether the file has unsaved modifications

			\return Whether the file has unsaved modifications
		*/
		bool IsModified() const;

		/*! Whether auto-analysis results have changed.

			\return Whether auto-analysis results have changed.
		*/
		bool IsAnalysisChanged() const;

		/*! Mark file as having unsaved changes
		*/
		void MarkFileModified();

		/*! Mark file as having been saved (inverse of MarkFileModified)
		*/
		void MarkFileSaved();

		bool IsSnapshotDataAppliedWithoutError() const;

		/*! Whether the FileMetadata is backed by a database, or if specified,
		    	a specific BinaryView type

			\param binaryViewType Type for the BinaryView
		 	\return Whether the FileMetadata is backed by a database
		*/
		bool IsBackedByDatabase(const std::string& binaryViewType = "") const;

		/*! Writes the current database (.bndb) out to the specified file.

		 	\param name path and filename to write the bndb to. Should have ".bndb" appended to it.
		 	\param data BinaryView to save the database from
		 	\param settings Special save options
		 	\return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& name, BinaryView* data, Ref<SaveSettings> settings);

		/*! Writes the current database (.bndb) out to the specified file.

		    \param name path and filename to write the bndb to. Should have ".bndb" appended to it.
		    \param data BinaryView to save the database from
		    \param progressCallback callback function to send save progress to.
		    \param settings Special save options
		    \return Whether the save was successful
		*/
		bool CreateDatabase(const std::string& name, BinaryView* data,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings);

		/*! Open an existing database from a given path

		 	\param path Path to the existing database
		 	\return The resulting BinaryView, if the load was successful
		*/
		Ref<BinaryView> OpenExistingDatabase(const std::string& path);

		/*! Open an existing database from a given path with a progress callback

		    \param path Path to the existing database
			\param progressCallback callback function to send load progress to.
		    \return The resulting BinaryView, if the load was successful
		*/
		Ref<BinaryView> OpenExistingDatabase(
		    const std::string& path, const std::function<bool(size_t progress, size_t total)>& progressCallback);
		Ref<BinaryView> OpenDatabaseForConfiguration(const std::string& path);

		/*! Save the current database to the already created file.

		 	Note: CreateDatabase should have been called prior to calling this.

			\param data BinaryView to save the data of
		    \param settings Special save options
		    \return Whether the save was successful
		*/
		bool SaveAutoSnapshot(BinaryView* data, Ref<SaveSettings> settings);

		/*! Save the current database to the already created file.

		    Note: CreateDatabase should have been called prior to calling this.

		    \param data BinaryView to save the data of
		    \param settings Special save options
		    \param progressCallback callback function to send save progress to
		    \return Whether the save was successful
		*/
		bool SaveAutoSnapshot(BinaryView* data,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback, Ref<SaveSettings> settings);
		void GetSnapshotData(
		    Ref<KeyValueStore> data, Ref<KeyValueStore> cache, const std::function<bool(size_t, size_t)>& progress);
		void ApplySnapshotData(BinaryView* file, Ref<KeyValueStore> data, Ref<KeyValueStore> cache,
		    const std::function<bool(size_t, size_t)>& progress, bool openForConfiguration = false,
		    bool restoreRawView = true);
		Ref<Database> GetDatabase();

		/*! Rebase the given BinaryView to a new address

			\param data BinaryView to rebase
		    \param address Address to rebase to
		    \return Whether the rebase was successful
		*/
		bool Rebase(BinaryView* data, uint64_t address);

		/*! Rebase the given BinaryView to a new address

			\param data BinaryView to rebase
		    \param address Address to rebase to
		    \param progressCallback Callback function to pass rebase progress to
		    \return Whether the rebase was successful
		*/
		bool Rebase(BinaryView* data, uint64_t address,
		    const std::function<bool(size_t progress, size_t total)>& progressCallback);
		bool CreateSnapshotedView(BinaryView* data, const std::string& viewName);
		bool CreateSnapshotedView(BinaryView* data, const std::string& viewName,
								  const std::function<bool(size_t progress, size_t total)>& progressCallback);

		/*! Run a function in a context in which any changes made to analysis will be added to an undo state.
			If the function returns false or throws an exception, any changes made within will be reverted.

			\param func Function to run in undo context
			\return Return status of function
			\throws std::exception If the called function throws an exception
		 */
		bool RunUndoableTransaction(std::function<bool()> func);

		/*! Start recording actions taken so they can be undone at some point

			\param anonymousAllowed Legacy interop: prevent empty calls to CommitUndoActions from affecting this
			                        undo state. Specifically for RunUndoableTransaction.
			\return Id of UndoEntry created, for passing to either CommitUndoActions or RevertUndoActions
		*/
		[[nodiscard]] std::string BeginUndoActions(bool anonymousAllowed = true);

		/*!  Commit the actions taken since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void CommitUndoActions(const std::string& id);

		/*!  Revert the actions taken since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void RevertUndoActions(const std::string& id);

		/*!  Forget the actions since a call to BeginUndoActions.

			\param id Id of UndoEntry created by BeginUndoActions
		*/
		void ForgetUndoActions(const std::string& id);

		/*! \return Whether it is possible to perform an Undo
		*/
		bool CanUndo();

		/*! Undo the last committed action in the undo database.
		*/
		bool Undo();

		/*! \return Whether it is possible to perform a Redo
		*/
		bool CanRedo();

		/*! Redo the last committed action in the undo database.
		*/
		bool Redo();

		std::vector<Ref<User>> GetUsers();
		std::vector<Ref<UndoEntry>> GetUndoEntries();
		std::vector<Ref<UndoEntry>> GetRedoEntries();
		Ref<UndoEntry> GetLastUndoEntry();
		Ref<UndoEntry> GetLastRedoEntry();
		std::optional<std::string> GetLastUndoEntryTitle();
		std::optional<std::string> GetLastRedoEntryTitle();
		void ClearUndoEntries();

		/*! Get the current View name, e.g. ``Linear:ELF``, ``Graph:PE``

		    \return The current view name
		*/
		std::string GetCurrentView();

		/*! Get the current offset in the current view

		    \return The current offset
		*/
		uint64_t GetCurrentOffset();

		/*! Navigate to the specified virtual address in the specified view

		 	\param view View name. e.g. ``Linear:ELF``, ``Graph:PE``
		 	\param offset Virtual address to navigate to
		 	\return Whether the navigation was successful.
		*/
		bool Navigate(const std::string& view, uint64_t offset);

		/*! Get the BinaryView for a specific View type

		    \param name View name. e.g. ``Linear:ELF``, ``Graph:PE``
		    \return The BinaryView, if it exists
		*/
		BinaryNinja::Ref<BinaryNinja::BinaryView> GetViewOfType(const std::string& name);

		/*! List of View names that exist within the current file

		    \return List of View Names
		*/
		std::vector<std::string> GetExistingViews() const;

		/*! Get the current Session ID for this file.

		 	\see This is used in Logger and LogRegistry to determine what tab logs are sent to.

		    \return Current Session ID
		*/
		size_t GetSessionId() const;

		/*! Explicitly unregister a binary view of the given type from this file.

		    \note There is no need to unregister a binary view in ordinary situations. Binary views will be
		    automatically unregistered from the file when the file itself is about to be freed. Also, when a
		    binary view with the same type is created, the old one is automatically unregistered from the file.

		    Only use this function when you wish to explicitly remove the binary view from the file. For example,
		    in the debugger, this method is used to remove the Debugger view from the file after the target exits.

		    This also does not necessarily free the binary, because there could be other references to it.

		    \param type the type of the view to unregister
		    \param data the binary view to unregister
		*/
		void UnregisterViewOfType(const std::string& type, BinaryNinja::Ref<BinaryNinja::BinaryView> data);

		Ref<ProjectFile> GetProjectFile() const;
		void SetProjectFile(Ref<ProjectFile> projectFile);
	};
}
