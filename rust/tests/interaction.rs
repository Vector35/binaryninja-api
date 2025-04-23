use std::path::PathBuf;

use binaryninja::binary_view::BinaryView;
use binaryninja::flowgraph::FlowGraph;
use binaryninja::headless::Session;
use binaryninja::interaction::{
    register_custom_interaction_handler, CustomInteractionHandler, CustomInterationHandlerTask,
    FormInput, FormResponses, MessageBoxButtonResult, MessageBoxButtonSet, MessageBoxIcon, Report,
    ReportCollection,
};

struct MyInteractionHandler {}
impl CustomInteractionHandler for MyInteractionHandler {
    fn show_plain_text_report(&mut self, _view: &BinaryView, _title: &str, _contents: &str) {
        todo!()
    }

    fn show_markdown_report(
        &mut self,
        _view: &BinaryView,
        _title: &str,
        _contents: &str,
        _plaintext: &str,
    ) {
        todo!()
    }

    fn show_html_report(
        &mut self,
        _view: &BinaryView,
        _title: &str,
        _contents: &str,
        _plaintext: &str,
    ) {
        todo!()
    }

    fn show_graph_report(&mut self, _view: &BinaryView, _title: &str, _graph: &FlowGraph) {
        todo!()
    }

    fn show_report_collection(&mut self, title: &str, reports: &ReportCollection) {
        assert_eq!(title, "show_report_collection_title");
        for (i, report) in reports.iter().enumerate() {
            assert_eq!(report.title().as_str(), format!("title_report_{i}"));
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

    fn get_form_input(&mut self, fields: &[FormInput], _title: &str) -> Option<Vec<FormResponses>> {
        if fields.len() != 1 {
            return None;
        }
        use binaryninja::interaction::FormInputType::*;
        match fields[0].type_() {
            Integer(_) => Some(vec![FormResponses::Integer(1337)]),
            DirectoryName(dir) => Some(vec![FormResponses::String(
                Some("example")
                    .into_iter()
                    .chain(dir.default())
                    .chain(dir.default_name())
                    .collect(),
            )]),
            Address(addr_form) => Some(vec![FormResponses::Address(
                addr_form.default().unwrap_or(0) + 0x10,
            )]),
            _ => None,
        }
    }

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
        _task: &CustomInterationHandlerTask,
    ) -> bool {
        todo!()
    }
}

#[test]
fn test_get_integer() {
    register_custom_interaction_handler(MyInteractionHandler {});
    let output = binaryninja::interaction::get_integer_input("get_int", "get_int_prompt");
    assert_eq!(output, Some(1337));
}

#[test]
fn test_get_directory() {
    register_custom_interaction_handler(MyInteractionHandler {});
    let output = binaryninja::interaction::get_directory_name_input("get_dir", "");
    assert_eq!(
        output.as_ref().map(|x| x.to_str().unwrap()),
        Some("example")
    );
}

#[test]
fn test_get_directory_default() {
    register_custom_interaction_handler(MyInteractionHandler {});
    let outputs = binaryninja::interaction::get_form_input(
        "get_dir_default",
        &mut [FormInput::directory_name_field(
            "get_dir_default",
            Some("_default_name"),
            Some("_default"),
        )],
    );
    assert_eq!(outputs.len(), 1);
    let FormResponses::String(output) = &outputs[0] else {
        panic!();
    };
    assert_eq!(output, "example_default_default_name");
}

#[test]
fn test_get_address() {
    register_custom_interaction_handler(MyInteractionHandler {});
    let output = binaryninja::interaction::get_address_input("address", "Address Prompt");
    assert_eq!(output, Some(0x10));
}

#[test]
fn test_show_report_collection() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");

    register_custom_interaction_handler(MyInteractionHandler {});
    let collection = ReportCollection::new();
    collection.add_text(&view, format!("title_report_0"), "contents");
    collection.add_markdown(
        &view,
        format!("title_report_1"),
        "# contents",
        "markdown_plain_text",
    );
    collection.add_html(
        &view,
        format!("title_report_2"),
        "<html>contents</html>",
        "html_plain_text",
    );
    collection.add_graph(&view, format!("title_report_3"), &FlowGraph::new());
    binaryninja::interaction::show_report_collection("show_report_collection_title", &collection);
}
