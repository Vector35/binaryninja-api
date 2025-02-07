use binaryninja::binary_view::BinaryViewExt;
use binaryninja::collaboration::{
    has_collaboration_support, NoNameChangeset, Remote, RemoteFileType, RemoteProject,
};
use binaryninja::headless::Session;
use binaryninja::symbol::{SymbolBuilder, SymbolType};
use rstest::*;
use serial_test::serial;
use std::path::PathBuf;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

// TODO: This cannot run in CI, as headless does not have collaboration, we should gate this.
// TODO: Why cant we create_project for the same project name? why does that fail.

// TODO: Remote connection / disconnection is NOT thread safe, the core needs to lock on each.
// TODO: Because of this we run these tests serially, this isnt _really_ an issue for real code, as
// TODO: Real code shouldnt be trying to connect to the same remote on multiple threads.

fn temp_project_scope<T: Fn(&RemoteProject)>(remote: &Remote, project_name: &str, cb: T) {
    if !remote.is_connected() {
        // TODO: Because connecting is not thread safe we wont check the error here, this is because we might already
        // TODO: be connecting in some other thread and will error out on this thread. But we _probably_ will
        // TODO: have connected by the time this errors out. Maybe?
        let _ = remote.connect();
    }
    let project = remote
        .create_project(project_name, "Test project for test purposes")
        .expect("Failed to create project");
    project.open().expect("Failed to open project");
    assert!(project.is_open(), "Project was not opened");
    // Clear out all the possible entries. This is to insure a clean slate.
    let files = project.files().expect("Failed to list files in project");
    for file in &files {
        project.delete_file(&file).expect("Failed to delete file");
    }
    let folders = project
        .folders()
        .expect("Failed to list folders in project");
    for folder in &folders {
        project
            .delete_folder(&folder)
            .expect("Failed to delete folder");
    }
    // Run task
    cb(&project);
    // Cleanup.
    project.close();
    assert!(!project.is_open(), "Project was not closed");
    remote
        .delete_project(&project)
        .expect("Failed to delete project");
}

#[rstest]
#[serial]
fn test_connection(_session: &Session) {
    if !has_collaboration_support() {
        eprintln!("No collaboration support, skipping test...");
        return;
    }
    let remotes = binaryninja::collaboration::known_remotes();
    let remote = remotes.iter().next().expect("No known remotes!");
    assert!(remote.connect().is_ok(), "Failed to connect to remote");
    remote
        .disconnect()
        .expect("Failed to disconnect from remote");
    assert!(!remote.is_connected(), "Connection was not disconnected");
}

#[rstest]
#[serial]
fn test_project_creation(_session: &Session) {
    if !has_collaboration_support() {
        eprintln!("No collaboration support, skipping test...");
        return;
    }
    let remotes = binaryninja::collaboration::known_remotes();
    let remote = remotes.iter().next().expect("No known remotes!");
    temp_project_scope(&remote, "test_creation", |project| {
        // Create the file than verify it by opening and checking contents.
        let created_file = project
            .create_file(
                "test_file",
                b"this is my file",
                "test_file",
                "",
                None,
                RemoteFileType::UnknownFileType,
            )
            .expect("Failed to create file in project");
        let created_file_id = created_file.id();
        assert_eq!(created_file.created_by(), remote.username());
        project
            .delete_file(&created_file)
            .expect("Failed to delete file");
        assert!(
            !project
                .get_file_by_id(created_file_id)
                .is_ok_and(|f| f.is_some()),
            "File was not deleted"
        );

        // Create a folder and verify it was created.
        let created_folder = project
            .create_folder("test_folder", "test_folder_desc", None)
            .unwrap();
        let created_folder_id = created_folder.id();
        assert_eq!(created_folder.name().as_str(), "test_folder");
        assert_eq!(created_folder.description().as_str(), "test_folder_desc");

        // Create a file in said folder and verify it exists in it.
        let created_folder_file = project
            .create_file(
                "test_folder_file",
                b"this is my file",
                "test_folder_file",
                "",
                Some(&created_folder),
                RemoteFileType::UnknownFileType,
            )
            .expect("Failed to create file in project folder");
        let created_folder_file_id = created_folder_file.id();
        // Verify the file exists in the folder.
        let check_folder_file = project
            .get_file_by_id(created_folder_file_id)
            .expect("Failed to get folder file by id")
            .unwrap();
        assert_eq!(check_folder_file.name().as_str(), "test_folder_file");
        assert_eq!(
            check_folder_file.folder().unwrap().unwrap().id(),
            created_folder_id,
            "Folder id does not match"
        );
        project
            .delete_file(&created_folder_file)
            .expect("Failed to delete file");

        // Verify the folder can be deleted.
        project
            .delete_folder(&created_folder)
            .expect("Failed to delete folder");
        assert!(
            !project
                .get_folder_by_id(created_folder_id)
                .is_ok_and(|f| f.is_some()),
            "Folder was not deleted"
        );
    })
}

#[rstest]
#[serial]
fn test_project_sync(_session: &Session) {
    if !has_collaboration_support() {
        eprintln!("No collaboration support, skipping test...");
        return;
    }
    let remotes = binaryninja::collaboration::known_remotes();
    let remote = remotes.iter().next().expect("No known remotes!");
    temp_project_scope(&remote, "test_sync", |project| {
        // Open a view so that we can upload it.
        let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
        let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
        let view_type = view.view_type();
        // Save the view to local database so that we can upload it
        assert!(
            view.file().create_database(out_dir.join("atox.obj.bndb")),
            "Failed to create local database"
        );
        // We should have a single snapshot.
        assert_eq!(view.file().database().unwrap().snapshots().len(), 1);
        // Update the entry function name.
        let entry_function = view
            .entry_point_function()
            .expect("Failed to get entry point function");
        let new_entry_func_symbol =
            SymbolBuilder::new(SymbolType::Function, "test", entry_function.start()).create();
        view.define_user_symbol(&new_entry_func_symbol);
        // Verify that we modified the binary
        assert_eq!(entry_function.symbol().raw_name().as_str(), "test");
        // Make new snapshot.
        assert!(view.file().save_auto_snapshot());
        // We should have two snapshots.
        assert_eq!(view.file().database().unwrap().snapshots().len(), 2);
        // Upload database and verify its remote file stuff
        let remote_file = project
            .upload_database(&view.file(), None, NoNameChangeset)
            .expect("Failed to upload database");
        assert_eq!(remote_file.name().as_str(), "atox.obj");
        assert_eq!(remote_file.created_by(), remote.username());
        assert_eq!(
            remote_file.file_type(),
            RemoteFileType::BinaryViewAnalysisFileType
        );
        // Delete local database and download remote one to verify changes.
        view.file().close();
        drop(view);
        // Verify that the remote file exists.
        project
            .get_file_by_id(remote_file.id())
            .expect("Failed to get remote file by id");
        // Download the remote database with our changes.
        let downloaded_file = remote_file
            .download_database(out_dir.join("downloaded_atox.obj.bndb"))
            .expect("Failed to download database");
        let downloaded_view = downloaded_file
            .view_of_type(view_type)
            .expect("Failed to open downloaded view");
        // Verify the changes in the entry function.
        let entry_function = downloaded_view
            .entry_point_function()
            .expect("Failed to get entry point function");
        assert_eq!(entry_function.symbol().raw_name().as_str(), "test");
        project
            .delete_file(&remote_file)
            .expect("Failed to delete file");
    });
}
