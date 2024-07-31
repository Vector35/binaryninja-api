#pragma once

#include <functional>
#include <optional>
#include <stdexcept>
#include "binaryninjacore.h"
#include "refcount.h"

namespace BinaryNinja
{
	class Metadata;

	/*!

		\ingroup project
	*/
	struct ProjectException : std::runtime_error
	{
		ProjectException(const std::string& desc) : std::runtime_error(desc.c_str()) {}
	};

	class ExternalLibrary;
	class Symbol;
	class Project;
	class ProjectFile;
	class ProjectFolder;

	/*!

	\ingroup project
	*/

	class ExternalLocation : public CoreRefCountObject<BNExternalLocation, BNNewExternalLocationReference, BNFreeExternalLocation>
	{
	public:
		ExternalLocation(BNExternalLocation* loc);

		Ref<Symbol> GetSourceSymbol();
		std::optional<uint64_t> GetTargetAddress();
		std::optional<std::string> GetTargetSymbol();
		Ref<ExternalLibrary> GetExternalLibrary();

		bool HasTargetAddress();
		bool HasTargetSymbol();

		bool SetTargetAddress(std::optional<uint64_t> address);
		bool SetTargetSymbol(std::optional<std::string> symbol);
		void SetExternalLibrary(Ref<ExternalLibrary> library);
	};

	/*!

	\ingroup project
	*/

	class ExternalLibrary : public CoreRefCountObject<BNExternalLibrary, BNNewExternalLibraryReference, BNFreeExternalLibrary>
	{
	public:
		ExternalLibrary(BNExternalLibrary* lib);

		std::string GetName() const;
		Ref<ProjectFile> GetBackingFile() const;

		void SetBackingFile(Ref<ProjectFile> file);
	};


	/*!
		\ingroup project
	*/
	class ProjectNotification
	{
	  private:
		BNProjectNotification m_callbacks;

		static bool BeforeOpenProjectCallback(void* ctxt, BNProject* project);
		static void AfterOpenProjectCallback(void* ctxt, BNProject* project);
		static bool BeforeCloseProjectCallback(void* ctxt, BNProject* project);
		static void AfterCloseProjectCallback(void* ctxt, BNProject* project);
		static bool BeforeProjectMetadataWrittenCallback(void* ctxt, BNProject* project, char* key, BNMetadata* value);
		static void AfterProjectMetadataWrittenCallback(void* ctxt, BNProject* project, char* key, BNMetadata* value);
		static bool BeforeProjectFileCreatedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static void AfterProjectFileCreatedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static bool BeforeProjectFileUpdatedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static void AfterProjectFileUpdatedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static bool BeforeProjectFileDeletedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static void AfterProjectFileDeletedCallback(void* ctxt, BNProject* project, BNProjectFile* projectFile);
		static bool BeforeProjectFolderCreatedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		static void AfterProjectFolderCreatedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		static bool BeforeProjectFolderUpdatedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		static void AfterProjectFolderUpdatedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		static bool BeforeProjectFolderDeletedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);
		static void AfterProjectFolderDeletedCallback(void* ctxt, BNProject* project, BNProjectFolder* projectFolder);

	  public:
		ProjectNotification();
		virtual ~ProjectNotification() {}

		BNProjectNotification* GetCallbacks() { return &m_callbacks; }

		virtual bool OnBeforeOpenProject(Project* project)
		{
			(void)project;
			return true;
		}

		virtual void OnAfterOpenProject(Project* project)
		{
			(void)project;
		}

		virtual bool OnBeforeCloseProject(Project* project)
		{
			(void)project;
			return true;
		}

		virtual void OnAfterCloseProject(Project* project)
		{
			(void)project;
		}

		virtual bool OnBeforeProjectMetadataWritten(Project* project, std::string& key, Metadata* value)
		{
			(void)project;
			(void)key;
			(void)value;
			return true;
		}

		virtual void OnAfterProjectMetadataWritten(Project* project, std::string& key, Metadata* value)
		{
			(void)project;
			(void)key;
			(void)value;
		}

		virtual bool OnBeforeProjectFileCreated(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
			return true;
		}

		virtual void OnAfterProjectFileCreated(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
		}

		virtual bool OnBeforeProjectFileUpdated(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
			return true;
		}

		virtual void OnAfterProjectFileUpdated(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
		}

		virtual bool OnBeforeProjectFileDeleted(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
			return true;
		}

		virtual void OnAfterProjectFileDeleted(Project* project, ProjectFile* projectFile)
		{
			(void)project;
			(void)projectFile;
		}

		virtual bool OnBeforeProjectFolderCreated(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
			return true;
		}

		virtual void OnAfterProjectFolderCreated(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
		}

		virtual bool OnBeforeProjectFolderUpdated(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
			return true;
		}

		virtual void OnAfterProjectFolderUpdated(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
		}

		virtual bool OnBeforeProjectFolderDeleted(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
			return true;
		}

		virtual void OnAfterProjectFolderDeleted(Project* project, ProjectFolder* projectFolder)
		{
			(void)project;
			(void)projectFolder;
		}
	};

	/*!

	\ingroup project
	*/
	class ProjectFolder : public CoreRefCountObject<BNProjectFolder, BNNewProjectFolderReference, BNFreeProjectFolder>
	{
	public:
		ProjectFolder(BNProjectFolder* folder);

		Ref<Project> GetProject() const;
		std::string GetId() const;
		std::string GetName() const;
		std::string GetDescription() const;
		void SetName(const std::string& name);
		void SetDescription(const std::string& description);
		Ref<ProjectFolder> GetParent() const;
		void SetParent(Ref<ProjectFolder> parent);
		bool Export(const std::string& destination, const std::function<bool(size_t progress, size_t total)>& progressCallback = {}) const;
	};

	/*!

	\ingroup project
	*/
	class ProjectFile : public CoreRefCountObject<BNProjectFile, BNNewProjectFileReference, BNFreeProjectFile>
	{
	public:
		ProjectFile(BNProjectFile* file);

		Ref<Project> GetProject() const;
		std::string GetPathOnDisk() const;
		bool ExistsOnDisk() const;
		std::string GetName() const;
		std::string GetDescription() const;
		void SetName(const std::string& name);
		void SetDescription(const std::string& description);
		std::string GetId() const;
		Ref<ProjectFolder> GetFolder() const;
		void SetFolder(Ref<ProjectFolder> folder);
		bool Export(const std::string& destination) const;
		int64_t GetCreationTimestamp() const;
	};


	/*!

		\ingroup project
	*/
	class Project : public CoreRefCountObject<BNProject, BNNewProjectReference, BNFreeProject>
	{
	  public:
		Project(BNProject* project);

		static Ref<Project> CreateProject(const std::string& path, const std::string& name);
		static Ref<Project> OpenProject(const std::string& path);
		static std::vector<Ref<Project>> GetOpenProjects();

		bool Open();
		bool Close();
		std::string GetId() const;
		bool IsOpen() const;
		std::string GetPath() const;
		std::string GetName() const;
		void SetName(const std::string& name);
		std::string GetDescription() const;
		void SetDescription(const std::string& description);

		Ref<Metadata> QueryMetadata(const std::string& key);
		bool StoreMetadata(const std::string& key, Ref<Metadata> value);
		void RemoveMetadata(const std::string& key);

		Ref<ProjectFolder> CreateFolderFromPath(const std::string& path, Ref<ProjectFolder> parent, const std::string& description,
			const std::function<bool(size_t progress, size_t total)>& progressCallback = {});
		Ref<ProjectFolder> CreateFolder(Ref<ProjectFolder> parent, const std::string& name, const std::string& description);
		Ref<ProjectFolder> CreateFolderUnsafe(Ref<ProjectFolder> parent, const std::string& name, const std::string& description, const std::string& id);
		std::vector<Ref<ProjectFolder>> GetFolders() const;
		Ref<ProjectFolder> GetFolderById(const std::string& id) const;
		void PushFolder(Ref<ProjectFolder> folder);
		bool DeleteFolder(Ref<ProjectFolder> folder, const std::function<bool(size_t progress, size_t total)>& progressCallback = {});

		Ref<ProjectFile> CreateFileFromPath(const std::string& path, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const std::function<bool(size_t progress, size_t total)>& progressCallback = {});
		Ref<ProjectFile> CreateFileFromPathUnsafe(const std::string& path, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const std::string& id, int64_t creationTimestamp, const std::function<bool(size_t progress, size_t total)>& progressCallback = {});
		Ref<ProjectFile> CreateFile_(const std::vector<uint8_t>& contents, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const std::function<bool(size_t progress, size_t total)>& progressCallback = {});
		Ref<ProjectFile> CreateFileUnsafe(const std::vector<uint8_t>& contents, Ref<ProjectFolder> folder, const std::string& name, const std::string& description, const std::string& id, int64_t creationTimestamp, const std::function<bool(size_t progress, size_t total)>& progressCallback = {});
		std::vector<Ref<ProjectFile>> GetFiles() const;
		Ref<ProjectFile> GetFileById(const std::string& id) const;
		Ref<ProjectFile> GetFileByPathOnDisk(const std::string& path);
		void PushFile(Ref<ProjectFile> file);
		bool DeleteFile_(Ref<ProjectFile> file);

		void RegisterNotification(ProjectNotification* notify);
		void UnregisterNotification(ProjectNotification* notify);

		void BeginBulkOperation();
		void EndBulkOperation();
	};
}
