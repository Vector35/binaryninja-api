use binaryninja::headless::Session;
use binaryninja::metadata::Metadata;
use binaryninja::project::Project;
use binaryninja::rc::Ref;
use rstest::*;
use std::time::SystemTime;

// TODO: We should use tempdir to manage the project directory.

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

fn unique_project(name: &str) -> String {
    format!("{}/{}", std::env::temp_dir().to_str().unwrap(), name)
}

#[rstest]
fn create_delete_empty(_session: &Session) {
    use std::fs::canonicalize;

    let project_name = "create_delete_empty_project";
    let project_path = unique_project(project_name);
    // create the project
    let project = Project::create(&project_path, project_name).expect("Failed to create project");
    project.open().unwrap();
    assert!(project.is_open());

    // check project data
    let project_path_received = project.path();
    assert_eq!(
        canonicalize(&project_path).unwrap(),
        canonicalize(project_path_received.to_string()).unwrap()
    );
    let project_name_received = project.name();
    assert_eq!(project_name, project_name_received.as_str());

    // close the project
    project.close().unwrap();
    assert!(!project.is_open());
    drop(project);

    // delete the project
    std::fs::remove_dir_all(project_path).unwrap();
}

#[rstest]
fn create_close_open_close(_session: &Session) {
    let project_name = "create_close_open_close";
    let project_path = unique_project(project_name);
    // create the project
    let project = Project::create(&project_path, project_name).expect("Failed to create project");
    project.open().unwrap();

    // get the project id
    let id = project.id();

    // close the project
    project.close().unwrap();
    drop(project);

    let project = Project::open_project(&project_path).expect("Failed to open project");
    // assert same id
    let new_id = project.id();
    assert_eq!(id, new_id);

    // close the project
    project.close().unwrap();
    drop(project);

    // delete the project
    std::fs::remove_dir_all(project_path).unwrap();
}

#[rstest]
fn modify_project(_session: &Session) {
    let project_name = "modify_project_project";
    let project_path = unique_project(project_name);
    // create the project
    let project = Project::create(&project_path, project_name).expect("Failed to create project");
    project.open().unwrap();

    // get project id
    let id = project.id();

    // create data and verify that data was created
    let data_1: Ref<Metadata> = "data1".into();
    let data_2: Ref<Metadata> = "data2".into();
    assert!(project.store_metadata("key", data_1.as_ref()));
    assert_eq!(
        data_1.get_string().unwrap(),
        project.query_metadata("key").get_string().unwrap()
    );
    project.remove_metadata("key");
    assert!(project.store_metadata("key", data_2.as_ref()));
    assert_eq!(
        data_2.get_string().unwrap(),
        project.query_metadata("key").get_string().unwrap()
    );

    // create file that will be imported to the project
    let tmp_folder_1_name = format!(
        "tmp_folder_{}",
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let tmp_folder_2_name = format!("{tmp_folder_1_name }_2");
    let tmp_folder_1 = format!(
        "{}/{tmp_folder_1_name}",
        std::env::temp_dir().to_str().unwrap()
    );
    let tmp_folder_2 = format!(
        "{}/{tmp_folder_2_name}",
        std::env::temp_dir().to_str().unwrap()
    );
    std::fs::create_dir(&tmp_folder_1).unwrap();
    std::fs::create_dir(&tmp_folder_2).unwrap();
    let input_file_1 = format!("{tmp_folder_2}/input_1");
    let input_file_2 = format!("{tmp_folder_2}/input_2");
    let input_file_1_data = b"input_1_data";
    let input_file_2_data = b"input_1_data";
    std::fs::write(&input_file_1, input_file_1_data).unwrap();
    std::fs::write(&input_file_2, input_file_2_data).unwrap();

    // create and delete folders
    let folder_1_desc = "desc_folder_1";
    let folder_1 = project
        .create_folder(None, "folder_1", folder_1_desc)
        .unwrap();
    let folder_2_desc = "AAAAA";
    let folder_2_id = "1717416787371";
    let folder_2 = unsafe {
        project
            .create_folder_unsafe(Some(&folder_1), "folder_2", folder_2_desc, folder_2_id)
            .unwrap()
    };
    let folder_3_desc = ""; // TODO "çàáÁÀ";
    let folder_3 = project
        .create_folder_from_path(&tmp_folder_1, None, folder_3_desc)
        .unwrap();
    let folder_4_desc = "";
    let _folder_4 = project
        .create_folder_from_path_with_progress(
            &tmp_folder_2,
            Some(&folder_3),
            folder_4_desc,
            |_, _| true,
        )
        .unwrap();
    let folder_5 = project
        .create_folder(None, "deleted_folder", folder_4_desc)
        .unwrap();

    assert_eq!(project.folders().unwrap().len(), 5);
    let last_folder = project.folder_by_id(folder_5.id()).unwrap();
    project.delete_folder(&last_folder).unwrap();
    assert_eq!(project.folders().unwrap().len(), 4);
    drop(folder_5);

    // create, import and delete file
    let file_1_data = b"data_1";
    let file_1_desc = "desc_file_1";
    let _file_1 = project
        .create_file(file_1_data, None, "file_1", file_1_desc)
        .unwrap();
    let file_2_data = b"data_2";
    let file_2_desc = "my desc";
    let file_2_id = "12334545";
    let _file_2 = unsafe {
        project.create_file_unsafe(
            file_2_data,
            Some(&folder_2),
            "file_2",
            file_2_desc,
            file_2_id,
            SystemTime::UNIX_EPOCH,
        )
    }
    .unwrap();
    let file_3_data = b"data\x023";
    let file_3_desc = "!";
    let _file_3 = project
        .create_file_with_progress(
            file_3_data,
            Some(&folder_1),
            "file_3",
            file_3_desc,
            |_, _| true,
        )
        .unwrap();
    let file_4_time = SystemTime::now();
    let file_4_data = b"data_4\x00_4";
    let file_4_desc = "";
    let file_4_id = "123123123";
    let _file_4 = unsafe {
        project.create_file_unsafe_with_progress(
            file_4_data,
            Some(&folder_3),
            "file_4",
            file_4_desc,
            file_4_id,
            file_4_time,
            |_, _| true,
        )
    }
    .unwrap();
    let file_5_desc = "desc";
    let _file_5 = project
        .create_file_from_path(&input_file_1, None, "file_5", file_5_desc)
        .unwrap();
    let file_6_time = SystemTime::now();
    let file_6_desc = "de";
    let file_6_id = "90218347";
    let _file_6 = unsafe {
        project.create_file_from_path_unsafe(
            &input_file_2,
            Some(&folder_3),
            "file_6",
            file_6_desc,
            file_6_id,
            file_6_time,
        )
    }
    .unwrap();
    let file_7 = project
        .create_file_from_path_with_progress(
            &input_file_2,
            Some(&folder_2),
            "file_7",
            "no",
            |_, _| true,
        )
        .unwrap();
    let file_8 = unsafe {
        project.create_file_from_path_unsafe_with_progress(
            &input_file_1,
            None,
            "file_7",
            "no",
            "92736528",
            SystemTime::now(),
            |_, _| true,
        )
    }
    .unwrap();

    assert_eq!(project.files().len(), 10);
    let file_a = project.file_by_id(file_8.id()).unwrap();
    let file_b = project.file_by_path(file_7.path_on_disk()).unwrap();
    project.delete_file(&file_a);
    project.delete_file(&file_b);
    assert_eq!(project.files().len(), 8);
    drop(file_8);
    drop(file_7);

    project.set_name("project_name");
    project.set_description("project_description");

    // close the project
    project.close().unwrap();
    drop(project);
    drop(folder_1);
    drop(folder_2);
    drop(folder_3);

    // reopen the project and verify the information store on it
    let project = Project::open_project(&project_path).expect("Failed to open project");

    // assert same id
    assert_eq!(id, project.id());

    // verify metadata
    assert_eq!(
        data_2.get_string().unwrap(),
        project.query_metadata("key").get_string().unwrap()
    );

    // check folders
    let folders = [
        ("folder_1", None),
        ("folder_2", Some(folder_2_id)),
        (&tmp_folder_1_name, None),
        (&tmp_folder_2_name, None),
    ];
    for folder in project.folders().unwrap().iter() {
        let found = folders
            .iter()
            .find(|f| folder.name().as_str() == f.0)
            .unwrap();
        if let Some(id) = found.1 {
            assert_eq!(folder.id().as_str(), id);
        }
    }

    // check files
    let files = [
        ("file_1", &file_1_data[..], None, None),
        ("file_2", &file_2_data[..], Some(file_2_id), None),
        ("file_3", &file_3_data[..], None, None),
        (
            "file_4",
            &file_4_data[..],
            Some(file_4_id),
            Some(file_4_time),
        ),
        ("file_5", &input_file_1_data[..], None, None),
        (
            "file_6",
            &input_file_2_data[..],
            Some(file_6_id),
            Some(file_6_time),
        ),
        ("input_1", &input_file_1_data[..], None, None),
        ("input_2", &input_file_2_data[..], None, None),
    ];
    for file in project.files().iter() {
        let found = files.iter().find(|f| file.name().as_str() == f.0).unwrap();
        if let Some(id) = found.2 {
            assert_eq!(file.id().as_str(), id);
        }
        if let Some(time) = found.3 {
            assert_eq!(
                file.creation_time()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                time.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            );
        }
        let content = std::fs::read(file.path_on_disk().as_str()).unwrap();
        assert_eq!(content, found.1);
    }

    assert_eq!(project.name().as_str(), "project_name");
    assert_eq!(project.description().as_str(), "project_description");

    // close the project
    project.close().unwrap();

    // delete the project
    std::fs::remove_dir_all(project_path).unwrap();
    std::fs::remove_dir_all(tmp_folder_1).unwrap();
    std::fs::remove_dir_all(tmp_folder_2).unwrap();
}
