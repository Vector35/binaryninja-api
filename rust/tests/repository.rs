use binaryninja::headless::Session;
use binaryninja::repository::RepositoryManager;
use rstest::*;

#[fixture]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_list(_session: Session) {
    let manager = RepositoryManager::default();
    let repositories = manager.repositories();
    for repository in &repositories {
        let repo_path = repository.path();
        let repository_by_path = manager.repository_by_path(repo_path).unwrap();
        assert_eq!(repository.url(), repository_by_path.url());
    }

    let repository = manager.default_repository();
    let _full_path = repository.full_path();
    let _path = repository.path();
    let _url = repository.url();
    let plugins = repository.plugins();
    for plugin in &plugins {
        let plugin_path = plugin.path();
        let plugin_by_path = repository.plugin_by_path(plugin_path).unwrap();
        assert_eq!(plugin.package_url(), plugin_by_path.package_url());
    }
}
