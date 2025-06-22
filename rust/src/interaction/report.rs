use std::fmt::Debug;
use std::ptr::NonNull;

use binaryninjacore_sys::*;

use crate::binary_view::BinaryView;
use crate::flowgraph::FlowGraph;
use crate::rc::{Ref, RefCountable};
use crate::string::{BnString, IntoCStr};

pub type ReportType = BNReportType;

#[repr(transparent)]
pub struct ReportCollection {
    handle: NonNull<BNReportCollection>,
}

impl ReportCollection {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNReportCollection>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNReportCollection>) -> Ref<Self> {
        unsafe { Ref::new(Self { handle }) }
    }

    pub fn new() -> Ref<Self> {
        let raw = unsafe { BNCreateReportCollection() };
        unsafe { Self::ref_from_raw(NonNull::new(raw).unwrap()) }
    }

    pub fn show(&self, title: &str) {
        let title = title.to_cstr();
        unsafe { BNShowReportCollection(title.as_ptr(), self.handle.as_ptr()) }
    }

    pub fn count(&self) -> usize {
        unsafe { BNGetReportCollectionCount(self.handle.as_ptr()) }
    }

    fn report_type(&self, i: usize) -> ReportType {
        unsafe { BNGetReportType(self.handle.as_ptr(), i) }
    }

    pub fn get(&self, i: usize) -> Report<'_> {
        Report::new(self, i)
    }

    fn view(&self, i: usize) -> Option<Ref<BinaryView>> {
        let raw = unsafe { BNGetReportView(self.handle.as_ptr(), i) };
        if raw.is_null() {
            return None;
        }
        Some(unsafe { BinaryView::ref_from_raw(raw) })
    }

    fn title(&self, i: usize) -> String {
        let raw = unsafe { BNGetReportTitle(self.handle.as_ptr(), i) };
        unsafe { BnString::into_string(raw) }
    }

    fn contents(&self, i: usize) -> String {
        let raw = unsafe { BNGetReportContents(self.handle.as_ptr(), i) };
        unsafe { BnString::into_string(raw) }
    }

    fn plain_text(&self, i: usize) -> String {
        let raw = unsafe { BNGetReportPlainText(self.handle.as_ptr(), i) };
        unsafe { BnString::into_string(raw) }
    }

    fn flow_graph(&self, i: usize) -> Option<Ref<FlowGraph>> {
        let raw = unsafe { BNGetReportFlowGraph(self.handle.as_ptr(), i) };
        match raw.is_null() {
            false => Some(unsafe { FlowGraph::ref_from_raw(raw) }),
            true => None,
        }
    }

    pub fn add_text(&self, view: &BinaryView, title: &str, contents: &str) {
        let title = title.to_cstr();
        let contents = contents.to_cstr();
        unsafe {
            BNAddPlainTextReportToCollection(
                self.handle.as_ptr(),
                view.handle,
                title.as_ptr(),
                contents.as_ptr(),
            )
        }
    }

    pub fn add_markdown(&self, view: &BinaryView, title: &str, contents: &str, plaintext: &str) {
        let title = title.to_cstr();
        let contents = contents.to_cstr();
        let plaintext = plaintext.to_cstr();
        unsafe {
            BNAddMarkdownReportToCollection(
                self.handle.as_ptr(),
                view.handle,
                title.as_ptr(),
                contents.as_ptr(),
                plaintext.as_ptr(),
            )
        }
    }

    pub fn add_html(&self, view: &BinaryView, title: &str, contents: &str, plaintext: &str) {
        let title = title.to_cstr();
        let contents = contents.to_cstr();
        let plaintext = plaintext.to_cstr();
        unsafe {
            BNAddHTMLReportToCollection(
                self.handle.as_ptr(),
                view.handle,
                title.as_ptr(),
                contents.as_ptr(),
                plaintext.as_ptr(),
            )
        }
    }

    pub fn add_graph(&self, view: &BinaryView, title: &str, graph: &FlowGraph) {
        let title = title.to_cstr();
        unsafe {
            BNAddGraphReportToCollection(
                self.handle.as_ptr(),
                view.handle,
                title.as_ptr(),
                graph.handle,
            )
        }
    }

    fn update_report_flow_graph(&self, i: usize, graph: &FlowGraph) {
        unsafe { BNUpdateReportFlowGraph(self.handle.as_ptr(), i, graph.handle) }
    }

    pub fn iter(&self) -> ReportCollectionIter<'_> {
        ReportCollectionIter::new(self)
    }
}

impl Debug for ReportCollection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportCollection")
            .field("count", &self.count())
            .finish()
    }
}

unsafe impl RefCountable for ReportCollection {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        let raw = unsafe { BNNewReportCollectionReference(handle.handle.as_ptr()) };
        unsafe { Self::ref_from_raw(NonNull::new(raw).unwrap()) }
    }

    unsafe fn dec_ref(handle: &Self) {
        unsafe { BNFreeReportCollection(handle.handle.as_ptr()) }
    }
}

impl ToOwned for ReportCollection {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

impl<'a> IntoIterator for &'a ReportCollection {
    type Item = Report<'a>;
    type IntoIter = ReportCollectionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub enum Report<'a> {
    PlainText(ReportPlainText<'a>),
    Markdown(ReportMarkdown<'a>),
    Html(ReportHtml<'a>),
    FlowGraph(ReportFlowGraph<'a>),
}

impl<'a> Report<'a> {
    fn new(collection: &'a ReportCollection, index: usize) -> Self {
        let inner = ReportInner { collection, index };
        match inner.type_() {
            ReportType::PlainTextReportType => Report::PlainText(ReportPlainText(inner)),
            ReportType::MarkdownReportType => Report::Markdown(ReportMarkdown(inner)),
            ReportType::HTMLReportType => Report::Html(ReportHtml(inner)),
            ReportType::FlowGraphReportType => Report::FlowGraph(ReportFlowGraph(inner)),
        }
    }

    fn _inner(&self) -> &ReportInner<'a> {
        match self {
            Report::PlainText(ReportPlainText(x))
            | Report::Markdown(ReportMarkdown(x))
            | Report::Html(ReportHtml(x))
            | Report::FlowGraph(ReportFlowGraph(x)) => x,
        }
    }

    pub fn view(&self) -> Option<Ref<BinaryView>> {
        self._inner().view()
    }

    pub fn title(&self) -> String {
        self._inner().title()
    }
}

pub struct ReportPlainText<'a>(ReportInner<'a>);

impl ReportPlainText<'_> {
    pub fn contents(&self) -> String {
        self.0.contents()
    }
}

pub struct ReportMarkdown<'a>(ReportInner<'a>);

impl ReportMarkdown<'_> {
    pub fn contents(&self) -> String {
        self.0.contents()
    }

    pub fn plaintext(&self) -> String {
        self.0.plain_text()
    }
}

pub struct ReportHtml<'a>(ReportInner<'a>);

impl ReportHtml<'_> {
    pub fn contents(&self) -> String {
        self.0.contents()
    }

    pub fn plaintext(&self) -> String {
        self.0.plain_text()
    }
}

pub struct ReportFlowGraph<'a>(ReportInner<'a>);

impl ReportFlowGraph<'_> {
    pub fn flow_graph(&self) -> Ref<FlowGraph> {
        self.0
            .flow_graph()
            .expect("Flow graph not available for flow graph report!")
    }

    pub fn update_report_flow_graph(&self, graph: &FlowGraph) {
        self.0.update_report_flow_graph(graph)
    }
}

struct ReportInner<'a> {
    collection: &'a ReportCollection,
    index: usize,
}

impl ReportInner<'_> {
    fn type_(&self) -> ReportType {
        self.collection.report_type(self.index)
    }

    fn view(&self) -> Option<Ref<BinaryView>> {
        self.collection.view(self.index)
    }

    fn title(&self) -> String {
        self.collection.title(self.index)
    }

    fn contents(&self) -> String {
        self.collection.contents(self.index)
    }

    fn plain_text(&self) -> String {
        self.collection.plain_text(self.index)
    }

    fn flow_graph(&self) -> Option<Ref<FlowGraph>> {
        self.collection.flow_graph(self.index)
    }

    fn update_report_flow_graph(&self, graph: &FlowGraph) {
        self.collection.update_report_flow_graph(self.index, graph)
    }
}

pub struct ReportCollectionIter<'a> {
    report: &'a ReportCollection,
    current_index: usize,
    count: usize,
}

impl<'a> ReportCollectionIter<'a> {
    pub fn new(report: &'a ReportCollection) -> Self {
        Self {
            report,
            current_index: 0,
            count: report.count(),
        }
    }

    pub fn collection(&self) -> &ReportCollection {
        self.report
    }
}

impl<'a> Iterator for ReportCollectionIter<'a> {
    type Item = Report<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        (self.current_index < self.count).then(|| {
            let result = Report::new(self.report, self.current_index);
            self.current_index += 1;
            result
        })
    }
}
