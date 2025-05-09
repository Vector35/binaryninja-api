use binaryninjacore_sys::*;

use crate::flowgraph::node::FlowGraphNode;
use crate::flowgraph::{BranchType, EdgePenStyle, ThemeColor};
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Ref};

#[derive(Clone, Debug, PartialEq)]
pub struct FlowGraphEdge {
    pub branch_type: BranchType,
    pub target: Ref<FlowGraphNode>,
    pub points: Vec<Point>,
    pub back_edge: bool,
    pub style: EdgeStyle,
}

impl FlowGraphEdge {
    pub fn from_raw(value: &BNFlowGraphEdge) -> Self {
        let raw_points = unsafe { std::slice::from_raw_parts(value.points, value.pointCount) };
        let points: Vec<_> = raw_points.iter().copied().map(Point::from).collect();
        Self {
            branch_type: value.type_,
            target: unsafe { FlowGraphNode::from_raw(value.target) }.to_owned(),
            points,
            back_edge: value.backEdge,
            style: value.style.into(),
        }
    }
}

impl CoreArrayProvider for FlowGraphEdge {
    type Raw = BNFlowGraphEdge;
    type Context = ();
    type Wrapped<'a> = FlowGraphEdge;
}

unsafe impl CoreArrayProviderInner for FlowGraphEdge {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _: &Self::Context) {
        BNFreeFlowGraphNodeEdgeList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(raw)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct Point {
    pub x: f32,
    pub y: f32,
}

impl Point {
    pub fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }
}

impl From<BNPoint> for Point {
    fn from(value: BNPoint) -> Self {
        Self {
            x: value.x,
            y: value.y,
        }
    }
}

impl From<Point> for BNPoint {
    fn from(value: Point) -> Self {
        Self {
            x: value.x,
            y: value.y,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct EdgeStyle {
    style: EdgePenStyle,
    width: usize,
    color: ThemeColor,
}

impl EdgeStyle {
    pub fn new(style: EdgePenStyle, width: usize, color: ThemeColor) -> Self {
        Self {
            style,
            width,
            color,
        }
    }
}

impl Default for EdgeStyle {
    fn default() -> Self {
        Self::new(EdgePenStyle::SolidLine, 0, ThemeColor::AddressColor)
    }
}

impl From<BNEdgeStyle> for EdgeStyle {
    fn from(style: BNEdgeStyle) -> Self {
        Self::new(style.style, style.width, style.color)
    }
}

impl From<EdgeStyle> for BNEdgeStyle {
    fn from(style: EdgeStyle) -> Self {
        Self {
            style: style.style,
            width: style.width,
            color: style.color,
        }
    }
}
