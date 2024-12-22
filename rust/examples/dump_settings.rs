use binaryninja::settings::Settings;

fn main() {
    println!("Starting session...");
    // This loads all the core architecture, platform, etc plugins
    let _headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    let settings = Settings::new();
    for key in &settings.keys() {
        let value = settings.get_string(key);
        let default_value = settings.get_property_string(key, "default");
        let title = settings.get_property_string(key, "title");
        let description = settings.get_property_string(key, "description");
        println!("{}:", key);
        println!("  value: {}", value);
        println!("  default_value: {}", default_value);
        println!("  title: {}", title);
        println!("  description: {}", description);
    }
}
