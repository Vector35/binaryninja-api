//! The [`QualifiedName`] is the canonical way to represent structured names in Binary Ninja.

use crate::rc::{CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{raw_to_string, strings_to_string_list, BnString};
use binaryninjacore_sys::*;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::ops::{Index, IndexMut};

/// A [`QualifiedName`] represents a name composed of multiple components, typically used for symbols
/// and type names within namespaces, classes, or modules.
///
/// # Creating a Qualified Name
///
/// ```
/// use binaryninja::qualified_name::QualifiedName;
///
/// // Uses the default separator "::"
/// let qn_vec = QualifiedName::new(vec!["my", "namespace", "func"]);
/// assert_eq!(qn_vec.to_string(), "my::namespace::func");
///
/// // Using `QualifiedName::from` will not split on the default separator "::".
/// let qn_from = QualifiedName::from("std::string");
/// assert_eq!(qn_from.len(), 1);
/// assert_eq!(qn_from.to_string(), "std::string");
/// ```
///
/// # Using a Custom Separator
///
/// While `::` is the default, you can specify a custom separator:
///
/// ```
/// use binaryninja::qualified_name::QualifiedName;
///
/// let qn = QualifiedName::new_with_separator(["a", "b", "c"], ".");
/// assert_eq!(qn.to_string(), "a.b.c");
/// ```
#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub struct QualifiedName {
    // TODO: Make this Option<String> where default is "::".
    pub separator: String,
    pub items: Vec<String>,
}

impl QualifiedName {
    pub fn from_raw(value: &BNQualifiedName) -> Self {
        // TODO: This could be improved...
        let raw_names = unsafe { std::slice::from_raw_parts(value.name, value.nameCount) };
        let items = raw_names
            .iter()
            .filter_map(|&raw_name| raw_to_string(raw_name as *const _))
            .collect();
        let separator = raw_to_string(value.join).unwrap();
        Self { items, separator }
    }

    pub fn from_owned_raw(value: BNQualifiedName) -> Self {
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

    pub fn free_raw(value: BNQualifiedName) {
        unsafe { BnString::free_raw(value.join) };
        unsafe { BNFreeStringList(value.name, value.nameCount) };
    }

    /// Creates a new [`QualifiedName`] with the default separator `::`.
    pub fn new<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::new_with_separator(items, "::")
    }

    /// Creates a new `QualifiedName` with a custom separator.
    pub fn new_with_separator<I, S>(items: I, separator: impl Into<String>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let items = items.into_iter().map(Into::into).collect::<Vec<String>>();
        Self {
            items,
            separator: separator.into(),
        }
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
    /// use binaryninja::qualified_name::QualifiedName;
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

impl Default for QualifiedName {
    fn default() -> Self {
        Self::new(Vec::<String>::new())
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

impl From<BnString> for QualifiedName {
    fn from(value: BnString) -> Self {
        Self {
            items: vec![value.to_string_lossy().to_string()],
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
