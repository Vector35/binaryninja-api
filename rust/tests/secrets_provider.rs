use binaryninja::headless::Session;
use binaryninja::secrets_provider::{CoreSecretsProvider, SecretsProvider};
use rstest::*;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn list_secrets_provider(_session: &Session) {
    let providers = CoreSecretsProvider::all();
    assert!(providers.len() > 0);
    let providers_again = CoreSecretsProvider::all();
    assert_eq!(providers.len(), providers_again.len());
}

struct MySecretsProvider {}

impl SecretsProvider for MySecretsProvider {
    fn has_data(&mut self, key: &str) -> bool {
        key == "my_key"
    }

    fn get_data(&mut self, key: &str) -> String {
        if key == "my_key" { "my_value" } else { "" }.to_string()
    }

    fn store_data(&mut self, _key: &str, _data: &str) -> bool {
        false
    }

    fn delete_data(&mut self, _key: &str) -> bool {
        false
    }
}

#[rstest]
fn custom_secrets_provider(_session: &Session) {
    let my_provider = CoreSecretsProvider::new("MySecretsProvider", MySecretsProvider {});
    assert!(my_provider.has_data("my_key"));
    assert!(!my_provider.has_data("not_my_key"));
    assert_eq!(my_provider.get_data("my_key").as_str(), "my_value");
}
