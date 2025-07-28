use std::borrow::Cow;
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::ops::{Index, IndexMut};

use binaryninjacore_sys::*;

use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{raw_to_string, strings_to_string_list, BnString, IntoCStr};
use crate::types::Type;

// TODO: Document usage, specifically how to make a qualified name and why it exists.
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub struct QualifiedName {
    // TODO: Make this Option<String> where default is "::".
    pub separator: String,
    pub items: Vec<String>,
}

impl QualifiedName {
    pub(crate) fn from_raw(value: &BNQualifiedName) -> Self {
        // TODO: This could be improved...
        let raw_names = unsafe { std::slice::from_raw_parts(value.name, value.nameCount) };
        let items = raw_names
            .iter()
            .filter_map(|&raw_name| raw_to_string(raw_name as *const _))
            .collect();
        let separator = raw_to_string(value.join).unwrap();
        Self { items, separator }
    }

    pub(crate) fn from_owned_raw(value: BNQualifiedName) -> Self {
        let result = Self::from_raw(&value);
        Self::free_raw(value);
        result
    }

    pub fn into_raw(value: Self) -> BNQualifiedName {
        let bn_join = BnString::new(&value.separator);
        BNQualifiedName {
            // NOTE: Leaking string list must be freed by core or us!
            name: strings_to_string_list(&value.items),
            // NOTE: Leaking string must be freed by core or us!
            join: BnString::into_raw(bn_join),
            nameCount: value.items.len(),
        }
    }

    pub(crate) fn free_raw(value: BNQualifiedName) {
        unsafe { BnString::free_raw(value.join) };
        unsafe { BNFreeStringList(value.name, value.nameCount) };
    }

    pub fn new(items: Vec<String>) -> Self {
        Self::new_with_separator(items, "::".to_string())
    }

    pub fn new_with_separator(items: Vec<String>, separator: String) -> Self {
        Self { items, separator }
    }

    pub fn with_item(&self, item: impl Into<String>) -> Self {
        let mut items = self.items.clone();
        items.push(item.into());
        Self::new_with_separator(items, self.separator.clone())
    }

    pub fn push(&mut self, item: String) {
        self.items.push(item);
    }

    pub fn pop(&mut self) -> Option<String> {
        self.items.pop()
    }

    pub fn insert(&mut self, index: usize, item: String) {
        if index <= self.items.len() {
            self.items.insert(index, item);
        }
    }

    pub fn split_last(&self) -> Option<(String, QualifiedName)> {
        self.items.split_last().map(|(a, b)| {
            (
                a.to_owned(),
                QualifiedName::new_with_separator(b.to_vec(), self.separator.clone()),
            )
        })
    }

    /// Replaces all occurrences of a substring with another string in all items of the `QualifiedName`
    /// and returns an owned version of the modified `QualifiedName`.
    ///
    /// # Example
    ///
    /// ```
    /// use binaryninja::types::qualified_name::QualifiedName;
    ///
    /// let qualified_name =
    ///     QualifiedName::new(vec!["my::namespace".to_string(), "mytype".to_string()]);
    /// let replaced = qualified_name.replace("my", "your");
    /// assert_eq!(
    ///     replaced.items,
    ///     vec!["your::namespace".to_string(), "yourtype".to_string()]
    /// );
    /// ```
    pub fn replace(&self, from: &str, to: &str) -> Self {
        Self {
            items: self
                .items
                .iter()
                .map(|item| item.replace(from, to))
                .collect(),
            separator: self.separator.clone(),
        }
    }

    /// Returns the last item, or `None` if it is empty.
    pub fn last(&self) -> Option<&String> {
        self.items.last()
    }

    /// Returns a mutable reference to the last item, or `None` if it is empty.
    pub fn last_mut(&mut self) -> Option<&mut String> {
        self.items.last_mut()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// A [`QualifiedName`] is empty if it has no items.
    ///
    /// If you want to know if the unqualified name is empty (i.e. no characters)
    /// you must first convert the qualified name to unqualified via the `to_string` method.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl IntoCStr for &QualifiedName {
    type Result = CString;

    fn to_cstr(self) -> Self::Result {
        self.to_string().to_cstr()
    }
}

impl From<String> for QualifiedName {
    fn from(value: String) -> Self {
        Self {
            items: vec![value],
            // TODO: See comment in struct def.
            separator: String::from("::"),
        }
    }
}

impl From<&str> for QualifiedName {
    fn from(value: &str) -> Self {
        Self::from(value.to_string())
    }
}

impl From<&String> for QualifiedName {
    fn from(value: &String) -> Self {
        Self::from(value.to_owned())
    }
}

impl From<Cow<'_, str>> for QualifiedName {
    fn from(value: Cow<'_, str>) -> Self {
        Self::from(value.to_string())
    }
}

impl From<Vec<String>> for QualifiedName {
    fn from(value: Vec<String>) -> Self {
        Self::new(value)
    }
}

impl From<Vec<&str>> for QualifiedName {
    fn from(value: Vec<&str>) -> Self {
        value
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .into()
    }
}

impl From<QualifiedName> for String {
    fn from(value: QualifiedName) -> Self {
        value.to_string()
    }
}

impl Index<usize> for QualifiedName {
    type Output = String;

    fn index(&self, index: usize) -> &Self::Output {
        &self.items[index]
    }
}

impl IndexMut<usize> for QualifiedName {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.items[index]
    }
}

impl Display for QualifiedName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.items.join(&self.separator))
    }
}

impl CoreArrayProvider for QualifiedName {
    type Raw = BNQualifiedName;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for QualifiedName {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeNameList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        QualifiedName::from_raw(raw)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct QualifiedNameAndType {
    pub name: QualifiedName,
    pub ty: Ref<Type>,
}

impl QualifiedNameAndType {
    pub(crate) fn from_raw(value: &BNQualifiedNameAndType) -> Self {
        Self {
            name: QualifiedName::from_raw(&value.name),
            ty: unsafe { Type::from_raw(value.type_).to_owned() },
        }
    }

    pub(crate) fn from_owned_raw(value: BNQualifiedNameAndType) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNQualifiedNameAndType {
        BNQualifiedNameAndType {
            name: QualifiedName::into_raw(value.name),
            type_: unsafe { Ref::into_raw(value.ty).handle },
        }
    }

    pub(crate) fn free_raw(value: BNQualifiedNameAndType) {
        QualifiedName::free_raw(value.name);
        let _ = unsafe { Type::ref_from_raw(value.type_) };
    }

    pub fn new(name: QualifiedName, ty: Ref<Type>) -> Self {
        Self { name, ty }
    }
}

impl<T> From<(T, Ref<Type>)> for QualifiedNameAndType
where
    T: Into<QualifiedName>,
{
    fn from(value: (T, Ref<Type>)) -> Self {
        Self {
            name: value.0.into(),
            ty: value.1,
        }
    }
}

impl<T> From<(T, &Type)> for QualifiedNameAndType
where
    T: Into<QualifiedName>,
{
    fn from(value: (T, &Type)) -> Self {
        let ty = value.1.to_owned();
        Self {
            name: value.0.into(),
            ty,
        }
    }
}

impl CoreArrayProvider for QualifiedNameAndType {
    type Raw = BNQualifiedNameAndType;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for QualifiedNameAndType {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeAndNameList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        QualifiedNameAndType::from_raw(raw)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct QualifiedNameTypeAndId {
    pub name: QualifiedName,
    pub ty: Ref<Type>,
    pub id: String,
}

impl QualifiedNameTypeAndId {
    pub(crate) fn from_raw(value: &BNQualifiedNameTypeAndId) -> Self {
        Self {
            name: QualifiedName::from_raw(&value.name),
            ty: unsafe { Type::from_raw(value.type_) }.to_owned(),
            id: raw_to_string(value.id).unwrap(),
        }
    }

    pub(crate) fn from_owned_raw(value: BNQualifiedNameTypeAndId) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNQualifiedNameTypeAndId {
        let bn_id = BnString::new(value.id);
        BNQualifiedNameTypeAndId {
            name: QualifiedName::into_raw(value.name),
            id: BnString::into_raw(bn_id),
            type_: unsafe { Ref::into_raw(value.ty) }.handle,
        }
    }

    pub(crate) fn free_raw(value: BNQualifiedNameTypeAndId) {
        QualifiedName::free_raw(value.name);
        let _ = unsafe { Type::ref_from_raw(value.type_) };
        let _ = unsafe { BnString::from_raw(value.id) };
    }
}

impl CoreArrayProvider for QualifiedNameTypeAndId {
    type Raw = BNQualifiedNameTypeAndId;
    type Context = ();
    type Wrapped<'a> = QualifiedNameTypeAndId;
}

unsafe impl CoreArrayProviderInner for QualifiedNameTypeAndId {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeIdList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        QualifiedNameTypeAndId::from_raw(raw)
    }
}
