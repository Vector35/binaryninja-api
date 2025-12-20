use binaryninja::settings::Settings;
use binaryninja::tracing::TracingLogListener;

fn main() {
    tracing_subscriber::fmt::init();
    let _listener = TracingLogListener::new().register();

    // This loads all the core architecture, platform, etc plugins
    let _headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    let settings = Settings::new();
    for key in &settings.keys() {
        let value = settings.get_string(key);
        let default_value = settings.get_property_string(key, "default");
        let title = settings.get_property_string(key, "title");
        let description = settings.get_property_string(key, "description");
        tracing::info!("{}:", key);
        tracing::info!("  value: {}", value);
        tracing::info!("  default_value: {}", default_value);
        tracing::info!("  title: {}", title);
        tracing::info!("  description: {}", description);
    }
}
