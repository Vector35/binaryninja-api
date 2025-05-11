use std::path::PathBuf;

use binaryninja::binary_view::BinaryView;
use binaryninja::flowgraph::FlowGraph;
use binaryninja::headless::Session;
use binaryninja::interaction::form::{Form, FormInputField};
use binaryninja::interaction::handler::{
    register_interaction_handler, InteractionHandler, InteractionHandlerTask,
};
use binaryninja::interaction::report::{Report, ReportCollection};
use binaryninja::interaction::{MessageBoxButtonResult, MessageBoxButtonSet, MessageBoxIcon};

struct MyInteractionHandler;

impl InteractionHandler for MyInteractionHandler {
    fn show_message_box(
        &mut self,
        _title: &str,
        _text: &str,
        _buttons: MessageBoxButtonSet,
        _icon: MessageBoxIcon,
    ) -> MessageBoxButtonResult {
        todo!()
    }

    fn open_url(&mut self, _url: &str) -> bool {
        todo!()
    }

    fn run_progress_dialog(
        &mut self,
        _title: &str,
        _can_cancel: bool,
        _task: &InteractionHandlerTask,
    ) -> bool {
        todo!()
    }

    fn show_plain_text_report(
        &mut self,
        _view: Option<&BinaryView>,
        _title: &str,
        _contents: &str,
    ) {
        todo!()
    }

    fn show_graph_report(&mut self, _view: Option<&BinaryView>, _title: &str, _graph: &FlowGraph) {
        todo!()
    }

    fn show_report_collection(&mut self, title: &str, reports: &ReportCollection) {
        assert_eq!(title, "show_report_collection_title");
        for (i, report) in reports.iter().enumerate() {
            assert_eq!(report.title(), format!("title_report_{i}"));
            match (i, report) {
                (0, Report::PlainText(x)) => {
                    assert_eq!(x.contents().as_str(), "contents");
                }
                (1, Report::Markdown(x)) => {
                    assert_eq!(x.contents().as_str(), "# contents");
                    assert_eq!(x.plaintext().as_str(), "markdown_plain_text");
                }
                (2, Report::Html(x)) => {
                    assert_eq!(x.contents().as_str(), "<html>contents</html>");
                    assert_eq!(x.plaintext().as_str(), "html_plain_text");
                }
                (3, Report::FlowGraph(x)) => {
                    assert_eq!(x.flow_graph().get_node_count(), 0);
                }
                _ => unreachable!(),
            }
        }
    }

    fn get_form_input(&mut self, form: &mut Form) -> bool {
        if form.fields.len() != 1 {
            return false;
        }

        match &mut form.fields[0] {
            FormInputField::Integer { ref mut value, .. } => {
                *value = 1337;
                true
            }
            FormInputField::Address {
                ref mut value,
                default,
                ..
            } => {
                *value = default.unwrap_or(0) + 0x10;
                true
            }
            FormInputField::DirectoryName {
                ref mut value,
                default,
                default_name,
                ..
            } => {
                let new_value = format!(
                    "example{}{}",
                    default.clone().unwrap_or_default(),
                    default_name.clone().unwrap_or_default()
                );
                *value = Some(new_value);
                true
            }
            _ => false,
        }
    }
}

#[test]
fn test_get_integer() {
    register_interaction_handler(MyInteractionHandler {});
    let output = binaryninja::interaction::get_integer_input("get_int", "get_int_prompt");
    assert_eq!(output, Some(1337));
}

#[test]
fn test_get_directory() {
    register_interaction_handler(MyInteractionHandler {});
    let output = binaryninja::interaction::get_directory_name_input("get_dir", "");
    assert_eq!(
        output.as_ref().map(|x| x.to_str().unwrap()),
        Some("example")
    );
}

#[test]
fn test_get_directory_default() {
    register_interaction_handler(MyInteractionHandler {});

    let mut my_form = Form::new("get_dir_default");
    my_form.add_field(FormInputField::DirectoryName {
        prompt: "get_dir_default".to_string(),
        default_name: Some("_default_name".to_string()),
        default: Some("_default".to_string()),
        value: None,
    });

    assert_eq!(my_form.prompt(), true);
    assert_eq!(
        my_form.fields[0].try_value_string(),
        Some("example_default_default_name".to_string())
    )
}

#[test]
fn test_get_address() {
    register_interaction_handler(MyInteractionHandler {});
    let output = binaryninja::interaction::get_address_input("address", "Address Prompt");
    assert_eq!(output, Some(0x10));
}

#[test]
fn test_show_report_collection() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");

    register_interaction_handler(MyInteractionHandler {});
    let collection = ReportCollection::new();
    collection.add_text(&view, "title_report_0", "contents");
    collection.add_markdown(&view, "title_report_1", "# contents", "markdown_plain_text");
    collection.add_html(
        &view,
        "title_report_2",
        "<html>contents</html>",
        "html_plain_text",
    );
    collection.add_graph(&view, "title_report_3", &FlowGraph::new());
    collection.show("show_report_collection_title");
}
