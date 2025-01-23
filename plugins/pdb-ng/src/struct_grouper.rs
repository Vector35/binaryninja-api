// Copyright 2022-2024 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{anyhow, Result};
use binaryninja::confidence::{Conf, MAX_CONFIDENCE};
use binaryninja::types::{MemberAccess, MemberScope, StructureBuilder, StructureType, Type};
use log::{debug, warn};
use std::cmp::Ordering;
use std::env;
use std::fmt::{Debug, Display, Formatter};

use crate::type_parser::ParsedMember;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MemberSize {
    index: usize,
    offset: u64,
    width: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedGroup {
    Single(usize),
    Struct(u64, Vec<ResolvedGroup>),
    Union(u64, Vec<ResolvedGroup>),
}

#[derive(Clone, PartialEq, Eq)]
struct WorkingStruct {
    index: Option<usize>,
    offset: u64,
    width: u64,
    is_union: bool,
    children: Vec<WorkingStruct>,
}

impl PartialOrd<Self> for WorkingStruct {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.end() < other.start() {
            Some(Ordering::Less)
        } else if other.end() < self.start() {
            Some(Ordering::Greater)
        } else if self.is_same(other) {
            Some(Ordering::Equal)
        } else {
            None
        }
    }
}

impl Debug for WorkingStruct {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.children.is_empty() {
            write!(f, "{:X} -> {:X}", self.start(), self.end())?;
            if let Some(index) = self.index {
                write!(f, " (#{:X})", index)?;
            } else {
                write!(f, " without index???")?;
            }
            Ok(())
        } else if self.is_union {
            write!(f, "union {:X} -> {:X} ", self.start(), self.end())?;
            if let Some(index) = self.index {
                write!(f, "with index {:X} ??? ", index)?;
            }
            f.debug_list().entries(self.children.iter()).finish()
        } else {
            write!(f, "struct {:X} -> {:X} ", self.start(), self.end())?;
            if let Some(index) = self.index {
                write!(f, "with index {:X} ??? ", index)?;
            }
            f.debug_list().entries(self.children.iter()).finish()
        }
    }
}

impl WorkingStruct {
    pub fn start(&self) -> u64 {
        self.offset
    }

    pub fn end(&self) -> u64 {
        self.offset + self.width
    }

    pub fn extend_to(&mut self, new_end: u64) {
        if new_end > self.end() {
            self.width = new_end - self.offset;
        }
    }

    // pub fn overlaps(&self, other: &WorkingStruct) -> bool {
    //     // If A starts after B ends
    //     if self.start() >= other.end() {
    //         return false;
    //     }
    //     // Or if B starts after A ends
    //     if other.start() >= self.end() {
    //         return false;
    //     }
    //     // Otherwise, one of the items starts before the other ends, so there is overlap
    //     return true;
    // }

    // pub fn contains(&self, other: &WorkingStruct) -> bool {
    //     // If other is fully contained within self
    //     self.start() <= other.start() && self.end() >= other.end()
    // }

    pub fn is_same(&self, other: &WorkingStruct) -> bool {
        // If self and other have the same range
        self.start() == other.start() && self.end() == other.end()
    }

    pub fn insert(&mut self, other: WorkingStruct, recursion: usize) -> Result<()> {
        log(|| {
            format!("{}self: {:#?}", "    ".repeat(recursion), self)
                .replace("\n", &("\n".to_owned() + &"    ".repeat(recursion)))
        });
        log(|| {
            format!("{}other: {:#?}", "    ".repeat(recursion), other)
                .replace("\n", &("\n".to_owned() + &"    ".repeat(recursion)))
        });

        self.extend_to(other.end());

        // There are 2 cases we have to deal with here:
        // a. `other` starts after the end of the last group => insert `other` into the last group
        // b. `other` starts before the end of the last group => collect all the children inserted after it starts and put them into a struct
        // start a new struct with `other`

        if self.children.is_empty() {
            self.children.push(other);
            return Ok(());
        }

        // This is really gross.
        // But also I need to ship this before I leave for France
        // TODO: Clean this up

        if other.start()
            >= self
                .children
                .last()
                .ok_or_else(|| anyhow!("Expected we have children #A"))?
                .end()
        {
            self.children.push(other);
        } else {
            // Create a structure with fields from self.children
            if self
                .children
                .last()
                .ok_or_else(|| anyhow!("Expected we have children #B"))?
                .index
                .is_none()
                && self
                    .children
                    .last()
                    .ok_or_else(|| anyhow!("Expected we have children #C"))?
                    .start()
                    < other.start()
            {
                self.children
                    .last_mut()
                    .ok_or_else(|| anyhow!("Expected we have children #D"))?
                    .insert(other, recursion + 1)?;
                return Ok(());
            }

            // If we're a union, we don't have to bother pushing a struct+union combo
            if self.is_union {
                self.children.push(WorkingStruct {
                    index: None,
                    offset: self.offset,
                    width: self.width,
                    is_union: false,
                    children: vec![other],
                });
                return Ok(());
            }

            let mut start_index = None;
            for (i, child) in self.children.iter().enumerate() {
                if child.start() >= other.start() {
                    start_index = Some(i);
                    break;
                }
            }
            if start_index.is_none() {
                return Err(anyhow!(
                    "Struct has overlapping member that cannot be resolved: {:#?}",
                    other
                ));
            }

            let struct_start = self.children
                [start_index.ok_or_else(|| anyhow!("Expected we have start index"))?]
            .offset;
            let struct_end = self
                .children
                .last()
                .ok_or_else(|| anyhow!("Expected we have start index"))?
                .end()
                .max(other.end());

            let struct_children = self
                .children
                .drain(start_index.ok_or_else(|| anyhow!("Expected we have start index"))?..)
                .collect::<Vec<_>>();
            self.children.push(WorkingStruct {
                index: None,
                offset: struct_start,
                width: struct_end - struct_start,
                is_union: true,
                children: vec![
                    WorkingStruct {
                        index: None,
                        offset: struct_start,
                        width: struct_end - struct_start,
                        is_union: false,
                        children: struct_children,
                    },
                    WorkingStruct {
                        index: None,
                        offset: struct_start,
                        width: struct_end - struct_start,
                        is_union: false,
                        children: vec![other],
                    },
                ],
            });

            // union {
            //     struct {
            //         int data0;
            //         int[2] data4;
            //         int dataC;
            //     };
            //     struct {
            //         int newdata0;
            //         ...
            //     };
            // };
        }

        // if other.start() < self.children[-1].end() {
        //     take children from other.start() until -1 and put them into a struct
        // }
        // else {
        //     add to self.children[-1], extend to fill
        // }

        Ok(())
    }

    pub fn to_resolved(mut self) -> ResolvedGroup {
        if let Some(index) = self.index {
            ResolvedGroup::Single(index)
        } else if self.is_union {
            if self.children.len() == 1 {
                self.children.remove(0).to_resolved()
            } else {
                // Collapse union of unions
                ResolvedGroup::Union(
                    self.offset,
                    self.children
                        .into_iter()
                        .flat_map(|child| match child.to_resolved() {
                            ResolvedGroup::Union(offset, children) if offset == self.offset => {
                                children
                            }
                            s => vec![s],
                        })
                        .collect(),
                )
            }
        } else {
            if self.children.len() == 1 {
                self.children.remove(0).to_resolved()
            } else {
                ResolvedGroup::Struct(
                    self.offset,
                    self.children
                        .into_iter()
                        .map(|child| child.to_resolved())
                        .collect(),
                )
            }
        }
    }
}

pub fn group_structure(
    name: &String,
    members: &Vec<ParsedMember>,
    structure: &mut StructureBuilder,
) -> Result<()> {
    // SO
    // PDBs handle trivial unions inside structures by just slamming all the fields together into
    // one big overlappy happy family. We need to reverse this and create out union structures
    // to properly represent the original source.

    // IN VISUAL FORM (if you are a visual person, like me):
    // struct {
    //     int foos[2];
    //     __offset(0):
    //     int foo1;
    //     int foo2;
    //     int bar;
    // }
    //
    // Into
    //
    // struct {
    //     union {
    //          int foos[2];
    //          struct {
    //              int foo1;
    //              int foo2;
    //          }
    //     }
    //     int bar;
    // }

    // Into internal rep
    let reps = members
        .iter()
        .enumerate()
        .map(|(i, member)| MemberSize {
            index: i,
            offset: member.offset,
            width: member.ty.contents.width(),
        })
        .collect::<Vec<_>>();

    log(|| format!("{} {:#x?}", name, members));
    log(|| format!("{} {:#x?}", name, reps));

    // Group them
    match resolve_struct_groups(reps) {
        Ok(groups) => {
            log(|| format!("{} {:#x?}", name, groups));

            // Apply grouped members
            apply_groups(members, structure, groups, 0);
        }
        Err(e) => {
            warn!("{} Could not resolve structure groups: {}", name, e);
            for member in members {
                structure.insert(
                    &member.ty,
                    member.name.clone(),
                    member.offset,
                    false,
                    member.access,
                    member.scope,
                );
            }
        }
    }

    Ok(())
}

fn apply_groups(
    members: &Vec<ParsedMember>,
    structure: &mut StructureBuilder,
    groups: Vec<ResolvedGroup>,
    offset: u64,
) {
    for (i, group) in groups.into_iter().enumerate() {
        match group {
            ResolvedGroup::Single(index) => {
                let member = &members[index];

                // TODO : Fix inner-offset being larger than `member.offset`

                if offset > member.offset {
                    structure.insert(
                        &member.ty,
                        member.name.clone(),
                        0,
                        false,
                        member.access,
                        member.scope,
                    );
                } else {
                    structure.insert(
                        &member.ty,
                        member.name.clone(),
                        member.offset - offset,
                        false,
                        member.access,
                        member.scope,
                    );
                }
            }
            ResolvedGroup::Struct(inner_offset, children) => {
                let mut inner = StructureBuilder::new();
                apply_groups(members, &mut inner, children, inner_offset);
                structure.insert(
                    &Conf::new(Type::structure(inner.finalize().as_ref()), MAX_CONFIDENCE),
                    format!("__inner{}", i),
                    inner_offset - offset,
                    false,
                    MemberAccess::PublicAccess,
                    MemberScope::NoScope,
                );
            }
            ResolvedGroup::Union(inner_offset, children) => {
                let mut inner = StructureBuilder::new();
                inner.structure_type(StructureType::UnionStructureType);
                apply_groups(members, &mut inner, children, inner_offset);
                structure.insert(
                    &Conf::new(Type::structure(inner.finalize().as_ref()), MAX_CONFIDENCE),
                    format!("__inner{}", i),
                    inner_offset - offset,
                    false,
                    MemberAccess::PublicAccess,
                    MemberScope::NoScope,
                );
            }
        }
    }
}

fn resolve_struct_groups(members: Vec<MemberSize>) -> Result<Vec<ResolvedGroup>> {
    // See if we care
    let mut has_overlapping = false;
    let mut last_end = 0;
    let mut max_width = 0;
    for member in &members {
        if member.offset < last_end {
            has_overlapping = true;
        }
        last_end = member.offset + member.width;
        max_width = max_width.max(member.offset + member.width);
    }

    // TODO: has overlapping is probably failing.
    if !has_overlapping {
        // Nothing overlaps, just add em directly
        return Ok(members
            .into_iter()
            .map(|member| ResolvedGroup::Single(member.index))
            .collect());
    }

    // Yes overlapping

    let mut groups = WorkingStruct {
        index: None,
        offset: 0,
        width: max_width,
        is_union: false,
        children: vec![],
    };
    for &member in &members {
        let member_group = WorkingStruct {
            index: Some(member.index),
            offset: member.offset,
            width: member.width,
            is_union: false,
            children: vec![],
        };
        groups.insert(member_group, 0)?;

        log(|| format!("GROUPS: {:#x?}", groups));
    }

    Ok(groups
        .children
        .into_iter()
        .map(|child| child.to_resolved())
        .collect())
}

#[test]
fn test_trivial() {
    assert_eq!(
        resolve_struct_groups(vec![
            MemberSize {
                index: 0,
                offset: 0,
                width: 1,
            },
            MemberSize {
                index: 1,
                offset: 1,
                width: 1,
            },
            MemberSize {
                index: 2,
                offset: 2,
                width: 1,
            },
            MemberSize {
                index: 3,
                offset: 3,
                width: 1,
            },
        ])
        .unwrap(),
        vec![
            ResolvedGroup::Single(0),
            ResolvedGroup::Single(1),
            ResolvedGroup::Single(2),
            ResolvedGroup::Single(3),
        ]
    );
}

#[test]
fn test_everything_everywhere() {
    assert_eq!(
        resolve_struct_groups(vec![
            MemberSize {
                index: 0,
                offset: 0,
                width: 1,
            },
            MemberSize {
                index: 1,
                offset: 0,
                width: 1,
            },
            MemberSize {
                index: 2,
                offset: 0,
                width: 1,
            },
            MemberSize {
                index: 3,
                offset: 0,
                width: 1,
            },
        ])
        .unwrap(),
        vec![ResolvedGroup::Union(
            0,
            vec![
                ResolvedGroup::Single(0),
                ResolvedGroup::Single(1),
                ResolvedGroup::Single(2),
                ResolvedGroup::Single(3),
            ]
        )]
    );
}

#[test]
fn test_unalignend() {
    assert_eq!(
        resolve_struct_groups(vec![
            MemberSize {
                index: 0,
                offset: 0,
                width: 4,
            },
            MemberSize {
                index: 1,
                offset: 4,
                width: 8,
            },
            MemberSize {
                index: 2,
                offset: 12,
                width: 4,
            },
            MemberSize {
                index: 3,
                offset: 0,
                width: 8,
            },
            MemberSize {
                index: 4,
                offset: 8,
                width: 8,
            },
        ])
        .unwrap(),
        vec![ResolvedGroup::Union(
            0,
            vec![
                ResolvedGroup::Struct(
                    0,
                    vec![
                        ResolvedGroup::Single(0),
                        ResolvedGroup::Single(1),
                        ResolvedGroup::Single(2),
                    ]
                ),
                ResolvedGroup::Struct(0, vec![ResolvedGroup::Single(3), ResolvedGroup::Single(4),]),
            ]
        )]
    );
}

#[test]
fn test_heap_vs_chunk_free_header() {
    assert_eq!(
        resolve_struct_groups(vec![
            MemberSize {
                index: 0,
                offset: 0,
                width: 16,
            },
            MemberSize {
                index: 1,
                offset: 0,
                width: 8,
            },
            MemberSize {
                index: 2,
                offset: 8,
                width: 24,
            },
        ])
        .unwrap(),
        vec![ResolvedGroup::Union(
            0,
            vec![
                ResolvedGroup::Single(0),
                ResolvedGroup::Struct(0, vec![ResolvedGroup::Single(1), ResolvedGroup::Single(2)])
            ]
        )]
    );
}

#[test]
fn test_kprcb() {
    assert_eq!(
        resolve_struct_groups(vec![
            MemberSize {
                index: 0,
                offset: 0,
                width: 8,
            },
            MemberSize {
                index: 1,
                offset: 8,
                width: 1,
            },
            MemberSize {
                index: 2,
                offset: 8,
                width: 1,
            },
            MemberSize {
                index: 3,
                offset: 9,
                width: 1,
            },
            MemberSize {
                index: 4,
                offset: 9,
                width: 1,
            },
            MemberSize {
                index: 5,
                offset: 10,
                width: 1,
            },
            MemberSize {
                index: 6,
                offset: 11,
                width: 1,
            },
            MemberSize {
                index: 7,
                offset: 12,
                width: 1,
            },
            MemberSize {
                index: 8,
                offset: 13,
                width: 1,
            },
            MemberSize {
                index: 9,
                offset: 14,
                width: 2,
            },
            MemberSize {
                index: 10,
                offset: 0,
                width: 16,
            },
            MemberSize {
                index: 11,
                offset: 16,
                width: 1,
            },
            MemberSize {
                index: 12,
                offset: 17,
                width: 1,
            },
            MemberSize {
                index: 13,
                offset: 18,
                width: 1,
            },
            MemberSize {
                index: 14,
                offset: 18,
                width: 1,
            },
            MemberSize {
                index: 15,
                offset: 19,
                width: 1,
            },
            MemberSize {
                index: 16,
                offset: 19,
                width: 1,
            },
            MemberSize {
                index: 17,
                offset: 20,
                width: 4,
            },
            MemberSize {
                index: 18,
                offset: 16,
                width: 8,
            },
        ])
        .unwrap(),
        vec![
            ResolvedGroup::Union(
                0,
                vec![
                    ResolvedGroup::Struct(
                        0,
                        vec![
                            ResolvedGroup::Single(0),
                            ResolvedGroup::Union(
                                8,
                                vec![ResolvedGroup::Single(1), ResolvedGroup::Single(2),]
                            ),
                            ResolvedGroup::Union(
                                9,
                                vec![ResolvedGroup::Single(3), ResolvedGroup::Single(4),]
                            ),
                            ResolvedGroup::Single(5),
                            ResolvedGroup::Single(6),
                            ResolvedGroup::Single(7),
                            ResolvedGroup::Single(8),
                            ResolvedGroup::Single(9)
                        ]
                    ),
                    ResolvedGroup::Single(10)
                ]
            ),
            ResolvedGroup::Union(
                16,
                vec![
                    ResolvedGroup::Struct(
                        16,
                        vec![
                            ResolvedGroup::Single(11),
                            ResolvedGroup::Single(12),
                            ResolvedGroup::Union(
                                18,
                                vec![ResolvedGroup::Single(13), ResolvedGroup::Single(14),]
                            ),
                            ResolvedGroup::Union(
                                19,
                                vec![ResolvedGroup::Single(15), ResolvedGroup::Single(16),]
                            ),
                            ResolvedGroup::Single(17)
                        ]
                    ),
                    ResolvedGroup::Single(18)
                ]
            )
        ]
    );
}

#[ignore]
#[test]
fn test_dispatcher_header() {
    /*
    XXX: This returns a different grouping which is still valid
    Basically it turns this:
    struct {
        unsigned char data0;
        union {
            unsigned char data1;
            struct {
                unsigned char data1_2;
                unsigned char data2;
                unsigned char data3;
            };
        };
    };

    into this:

    struct {
        unsigned char data0;
        union {
            unsigned char data1;
            unsigned char data1_2;
        };
        unsigned char data2;
        unsigned char data3;
    };
     */

    assert_eq!(
        resolve_struct_groups(vec![
            MemberSize {
                index: 0x0,
                offset: 0x0,
                width: 0x4,
            },
            MemberSize {
                index: 0x1,
                offset: 0x0,
                width: 0x4,
            },
            MemberSize {
                index: 0x2,
                offset: 0x0,
                width: 0x1,
            },
            MemberSize {
                index: 0x3,
                offset: 0x1,
                width: 0x1,
            },
            MemberSize {
                index: 0x4,
                offset: 0x2,
                width: 0x1,
            },
            MemberSize {
                index: 0x5,
                offset: 0x3,
                width: 0x1,
            },
            MemberSize {
                index: 0x6,
                offset: 0x0,
                width: 0x1,
            },
            MemberSize {
                index: 0x7,
                offset: 0x1,
                width: 0x1,
            },
            MemberSize {
                index: 0x8,
                offset: 0x1,
                width: 0x1,
            },
            MemberSize {
                index: 0x9,
                offset: 0x2,
                width: 0x1,
            },
            MemberSize {
                index: 0xa,
                offset: 0x3,
                width: 0x1,
            },
            MemberSize {
                index: 0xb,
                offset: 0x3,
                width: 0x1,
            },
            MemberSize {
                index: 0xc,
                offset: 0x0,
                width: 0x1,
            },
            MemberSize {
                index: 0xd,
                offset: 0x1,
                width: 0x1,
            },
            MemberSize {
                index: 0xe,
                offset: 0x1,
                width: 0x1,
            },
            MemberSize {
                index: 0xf,
                offset: 0x2,
                width: 0x1,
            },
            MemberSize {
                index: 0x10,
                offset: 0x3,
                width: 0x1,
            },
            MemberSize {
                index: 0x11,
                offset: 0x0,
                width: 0x1,
            },
            MemberSize {
                index: 0x12,
                offset: 0x1,
                width: 0x1,
            },
            MemberSize {
                index: 0x13,
                offset: 0x1,
                width: 0x1,
            },
            MemberSize {
                index: 0x14,
                offset: 0x2,
                width: 0x1,
            },
            MemberSize {
                index: 0x15,
                offset: 0x3,
                width: 0x1,
            },
            MemberSize {
                index: 0x16,
                offset: 0x0,
                width: 0x1,
            },
            MemberSize {
                index: 0x17,
                offset: 0x1,
                width: 0x1,
            },
            MemberSize {
                index: 0x18,
                offset: 0x2,
                width: 0x1,
            },
            MemberSize {
                index: 0x19,
                offset: 0x2,
                width: 0x1,
            },
            MemberSize {
                index: 0x1a,
                offset: 0x3,
                width: 0x1,
            },
            MemberSize {
                index: 0x1b,
                offset: 0x3,
                width: 0x1,
            },
            MemberSize {
                index: 0x1c,
                offset: 0x0,
                width: 0x1,
            },
            MemberSize {
                index: 0x1d,
                offset: 0x1,
                width: 0x1,
            },
            MemberSize {
                index: 0x1e,
                offset: 0x2,
                width: 0x1,
            },
            MemberSize {
                index: 0x1f,
                offset: 0x3,
                width: 0x1,
            },
            MemberSize {
                index: 0x20,
                offset: 0x4,
                width: 0x4,
            },
            MemberSize {
                index: 0x21,
                offset: 0x8,
                width: 0x10,
            },
        ])
        .unwrap(),
        vec![
            ResolvedGroup::Union(
                0,
                vec![
                    ResolvedGroup::Single(0x0),
                    ResolvedGroup::Single(0x1),
                    ResolvedGroup::Struct(
                        0,
                        vec![
                            ResolvedGroup::Single(0x2),
                            ResolvedGroup::Single(0x3),
                            ResolvedGroup::Single(0x4),
                            ResolvedGroup::Single(0x5),
                        ]
                    ),
                    ResolvedGroup::Struct(
                        0,
                        vec![
                            ResolvedGroup::Single(0x6),
                            ResolvedGroup::Union(
                                1,
                                vec![
                                    ResolvedGroup::Single(0x7),
                                    ResolvedGroup::Struct(
                                        1,
                                        vec![
                                            ResolvedGroup::Single(0x8),
                                            ResolvedGroup::Single(0x9),
                                            ResolvedGroup::Union(
                                                3,
                                                vec![
                                                    ResolvedGroup::Single(0xa),
                                                    ResolvedGroup::Single(0xb),
                                                ]
                                            ),
                                        ]
                                    ),
                                ]
                            ),
                        ]
                    ),
                    ResolvedGroup::Struct(
                        0,
                        vec![
                            ResolvedGroup::Single(0xc),
                            ResolvedGroup::Union(
                                1,
                                vec![
                                    ResolvedGroup::Single(0xd),
                                    ResolvedGroup::Struct(
                                        1,
                                        vec![
                                            ResolvedGroup::Single(0xe),
                                            ResolvedGroup::Single(0xf),
                                            ResolvedGroup::Single(0x10),
                                        ]
                                    )
                                ]
                            ),
                        ]
                    ),
                    ResolvedGroup::Struct(
                        0,
                        vec![
                            ResolvedGroup::Single(0x11),
                            ResolvedGroup::Union(
                                1,
                                vec![
                                    ResolvedGroup::Single(0x12),
                                    ResolvedGroup::Struct(
                                        1,
                                        vec![
                                            ResolvedGroup::Single(0x13),
                                            ResolvedGroup::Single(0x14),
                                            ResolvedGroup::Single(0x15),
                                        ]
                                    )
                                ]
                            ),
                        ]
                    ),
                    ResolvedGroup::Struct(
                        0,
                        vec![
                            ResolvedGroup::Single(0x16),
                            ResolvedGroup::Single(0x17),
                            ResolvedGroup::Union(
                                2,
                                vec![
                                    ResolvedGroup::Single(0x18),
                                    ResolvedGroup::Struct(
                                        2,
                                        vec![
                                            ResolvedGroup::Single(0x19),
                                            ResolvedGroup::Union(
                                                2,
                                                vec![
                                                    ResolvedGroup::Single(0x1a),
                                                    ResolvedGroup::Single(0x1b),
                                                ]
                                            )
                                        ]
                                    )
                                ]
                            ),
                        ]
                    ),
                    ResolvedGroup::Struct(
                        0,
                        vec![
                            ResolvedGroup::Single(0x1c),
                            ResolvedGroup::Single(0x1d),
                            ResolvedGroup::Single(0x1e),
                            ResolvedGroup::Single(0x1f),
                        ]
                    ),
                ]
            ),
            ResolvedGroup::Single(0x20),
            ResolvedGroup::Single(0x21),
        ]
    )
}

#[ignore]
#[test]
fn test_bool_modifier() {
    assert_eq!(
        resolve_struct_groups(vec![
            MemberSize {
                index: 0,
                offset: 8,
                width: 1,
            },
            MemberSize {
                index: 1,
                offset: 12,
                width: 8,
            },
            MemberSize {
                index: 2,
                offset: 16,
                width: 1,
            },
        ])
        .unwrap_err()
        .to_string(),
        format!(
            "Struct has overlapping member that cannot be resolved: {:#?}",
            MemberSize {
                index: 2,
                offset: 16,
                width: 1,
            }
        )
    );
}

/// Whoops I'm not in PDBParserInstance
fn log<F: FnOnce() -> D, D: Display>(msg: F) {
    // println!("{}", msg());
    if env::var("BN_DEBUG_PDB").is_ok() {
        debug!("{}", msg());
    }
}
