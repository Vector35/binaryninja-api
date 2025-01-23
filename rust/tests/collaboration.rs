use binaryninja::headless::Session;
use rstest::*;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

// TODO: This cannot run in CI, as headless does not have collaboration, we should gate this.

#[rstest]
fn test_connection(_session: &Session) {
    let remotes = binaryninja::collaboration::known_remotes();
    for remote in remotes.iter() {
        // TODO: This api needs a serious rework.
        remote.connect::<String, String>(None).unwrap();
        println!("{}: {}", remote.name(), remote.address());
        let projects = remote.projects().unwrap();
        for project in projects.iter() {
            println!("{}/{}", remote.name(), project.name());
            // let files = project.files().unwrap();
            // for file in files.iter() {
            //     println!("{}/{}/{}", remote.name(), project.name(), file.name());
            // }
        }
    }
}
