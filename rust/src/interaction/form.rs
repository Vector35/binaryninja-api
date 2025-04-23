use std::ffi::c_char;

use binaryninjacore_sys::*;

use crate::binary_view::BinaryView;
use crate::rc::{Array, Ref};
use crate::string::{raw_to_string, strings_to_string_list, BnString, IntoCStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    pub title: String,
    pub fields: Vec<FormInputField>,
}

impl Form {
    pub fn new(title: impl Into<String>) -> Self {
        Self::new_with_fields(title, vec![])
    }

    pub fn new_with_fields(title: impl Into<String>, fields: Vec<FormInputField>) -> Self {
        Self {
            title: title.into(),
            fields,
        }
    }

    pub fn add_field(&mut self, field: FormInputField) {
        self.fields.push(field);
    }

    /// Prompt the user (or interaction handler) for the form input.
    ///
    /// Updates the field's values and returns whether the form was accepted or not.
    pub fn prompt(&mut self) -> bool {
        let title = self.title.clone().to_cstr();
        let mut raw_fields = self
            .fields
            .iter()
            .map(FormInputField::into_raw)
            .collect::<Vec<_>>();
        let success =
            unsafe { BNGetFormInput(raw_fields.as_mut_ptr(), raw_fields.len(), title.as_ptr()) };
        // Update the fields with the new field values.
        self.fields = raw_fields
            .into_iter()
            .map(FormInputField::from_owned_raw)
            .collect();
        success
    }

    pub fn get_field_with_name(&self, name: &str) -> Option<&FormInputField> {
        self.fields
            .iter()
            .find(|field| field.try_prompt() == Some(name.to_string()))
    }
}

/// A field within a form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormInputField {
    Label {
        prompt: String,
    },
    Separator,
    TextLine {
        prompt: String,
        default: Option<String>,
        value: Option<String>,
    },
    MultilineText {
        prompt: String,
        default: Option<String>,
        value: Option<String>,
    },
    Integer {
        prompt: String,
        default: Option<i64>,
        value: i64,
    },
    Address {
        prompt: String,
        view: Option<Ref<BinaryView>>,
        current_address: u64,
        default: Option<u64>,
        value: u64,
    },
    Choice {
        prompt: String,
        choices: Vec<String>,
        default: Option<usize>,
        value: usize,
    },
    OpenFileName {
        prompt: String,
        /// File extension to filter on.
        extension: Option<String>,
        default: Option<String>,
        value: Option<String>,
    },
    SaveFileName {
        prompt: String,
        /// File extension to filter on.
        extension: Option<String>,
        /// Default file name to fill.
        default_name: Option<String>,
        default: Option<String>,
        value: Option<String>,
    },
    DirectoryName {
        prompt: String,
        default_name: Option<String>,
        default: Option<String>,
        value: Option<String>,
    },
}

impl FormInputField {
    pub fn from_raw(value: &BNFormInputField) -> Self {
        let prompt = raw_to_string(value.prompt).unwrap_or_default();
        let view = match value.view.is_null() {
            false => Some(unsafe { BinaryView::from_raw(value.view) }.to_owned()),
            true => None,
        };
        let name_default = value
            .hasDefault
            .then_some(raw_to_string(value.defaultName).unwrap_or_default());
        let string_default = value
            .hasDefault
            .then_some(raw_to_string(value.stringDefault).unwrap_or_default());
        let int_default = value.hasDefault.then_some(value.intDefault);
        let address_default = value.hasDefault.then_some(value.addressDefault);
        let index_default = value.hasDefault.then_some(value.indexDefault);
        let extension = raw_to_string(value.ext);
        let current_address = value.currentAddress;
        let string_result = raw_to_string(value.stringResult);
        let int_result = value.intResult;
        let address_result = value.addressResult;
        let index_result = value.indexResult;
        match value.type_ {
            BNFormInputFieldType::LabelFormField => Self::Label { prompt },
            BNFormInputFieldType::SeparatorFormField => Self::Separator,
            BNFormInputFieldType::TextLineFormField => Self::TextLine {
                prompt,
                default: string_default,
                value: string_result,
            },
            BNFormInputFieldType::MultilineTextFormField => Self::MultilineText {
                prompt,
                default: string_default,
                value: string_result,
            },
            BNFormInputFieldType::IntegerFormField => Self::Integer {
                prompt,
                default: int_default,
                value: int_result,
            },
            BNFormInputFieldType::AddressFormField => Self::Address {
                prompt,
                view,
                current_address,
                default: address_default,
                value: address_result,
            },
            BNFormInputFieldType::ChoiceFormField => Self::Choice {
                prompt,
                choices: vec![],
                default: index_default,
                value: index_result,
            },
            BNFormInputFieldType::OpenFileNameFormField => Self::OpenFileName {
                prompt,
                extension,
                default: string_default,
                value: string_result,
            },
            BNFormInputFieldType::SaveFileNameFormField => Self::SaveFileName {
                prompt,
                extension,
                default_name: name_default,
                default: string_default,
                value: string_result,
            },
            BNFormInputFieldType::DirectoryNameFormField => Self::DirectoryName {
                prompt,
                default_name: name_default,
                default: string_default,
                value: string_result,
            },
        }
    }

    pub fn from_owned_raw(value: BNFormInputField) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub fn into_raw(&self) -> BNFormInputField {
        let bn_prompt = BnString::new(self.try_prompt().unwrap_or_default());
        let bn_extension = BnString::new(self.try_extension().unwrap_or_default());
        let bn_default_string = BnString::new(self.try_default_string().unwrap_or_default());
        let bn_default_name = BnString::new(self.try_default_name().unwrap_or_default());
        let bn_value_string = BnString::new(self.try_value_string().unwrap_or_default());
        // Expected to be freed by [`FormInputField::free_raw`].
        BNFormInputField {
            type_: self.as_type(),
            prompt: BnString::into_raw(bn_prompt),
            view: match self.try_view() {
                None => std::ptr::null_mut(),
                Some(view) => unsafe { Ref::into_raw(view) }.handle,
            },
            currentAddress: self.try_current_address().unwrap_or_default(),
            choices: match self.try_choices() {
                None => std::ptr::null_mut(),
                Some(choices) => strings_to_string_list(choices.as_slice()) as *mut *const c_char,
            },
            // NOTE: `count` is the length of the `choices` array.
            count: self.try_choices().unwrap_or_default().len(),
            ext: BnString::into_raw(bn_extension),
            defaultName: BnString::into_raw(bn_default_name),
            intResult: self.try_value_int().unwrap_or_default(),
            addressResult: self.try_value_address().unwrap_or_default(),
            stringResult: BnString::into_raw(bn_value_string),
            indexResult: self.try_value_index().unwrap_or_default(),
            hasDefault: self.try_has_default().unwrap_or_default(),
            intDefault: self.try_default_int().unwrap_or_default(),
            addressDefault: self.try_default_address().unwrap_or_default(),
            stringDefault: BnString::into_raw(bn_default_string),
            indexDefault: self.try_default_index().unwrap_or_default(),
        }
    }

    pub fn free_raw(value: BNFormInputField) {
        unsafe {
            BnString::free_raw(value.defaultName as *mut c_char);
            BnString::free_raw(value.prompt as *mut c_char);
            BnString::free_raw(value.ext as *mut c_char);
            BnString::free_raw(value.stringDefault as *mut c_char);
            BnString::free_raw(value.stringResult);
            // TODO: Would like access to a `Array::free_raw` or something.
            Array::<BnString>::new(value.choices as *mut *mut c_char, value.count, ());
            // Free the view ref if provided.
            if !value.view.is_null() {
                BinaryView::ref_from_raw(value.view);
            }
        }
    }

    pub fn as_type(&self) -> BNFormInputFieldType {
        match self {
            FormInputField::Label { .. } => BNFormInputFieldType::LabelFormField,
            FormInputField::Separator => BNFormInputFieldType::SeparatorFormField,
            FormInputField::TextLine { .. } => BNFormInputFieldType::TextLineFormField,
            FormInputField::MultilineText { .. } => BNFormInputFieldType::MultilineTextFormField,
            FormInputField::Integer { .. } => BNFormInputFieldType::IntegerFormField,
            FormInputField::Address { .. } => BNFormInputFieldType::AddressFormField,
            FormInputField::Choice { .. } => BNFormInputFieldType::ChoiceFormField,
            FormInputField::OpenFileName { .. } => BNFormInputFieldType::OpenFileNameFormField,
            FormInputField::SaveFileName { .. } => BNFormInputFieldType::SaveFileNameFormField,
            FormInputField::DirectoryName { .. } => BNFormInputFieldType::DirectoryNameFormField,
        }
    }

    /// Mapping to the [`BNFormInputField::prompt`] field.
    pub fn try_prompt(&self) -> Option<String> {
        match self {
            FormInputField::Label { prompt, .. } => Some(prompt.clone()),
            FormInputField::Separator => None,
            FormInputField::TextLine { prompt, .. } => Some(prompt.clone()),
            FormInputField::MultilineText { prompt, .. } => Some(prompt.clone()),
            FormInputField::Integer { prompt, .. } => Some(prompt.clone()),
            FormInputField::Address { prompt, .. } => Some(prompt.clone()),
            FormInputField::Choice { prompt, .. } => Some(prompt.clone()),
            FormInputField::OpenFileName { prompt, .. } => Some(prompt.clone()),
            FormInputField::SaveFileName { prompt, .. } => Some(prompt.clone()),
            FormInputField::DirectoryName { prompt, .. } => Some(prompt.clone()),
        }
    }

    /// Mapping to the [`BNFormInputField::view`] field.
    pub fn try_view(&self) -> Option<Ref<BinaryView>> {
        match self {
            FormInputField::Address { view, .. } => view.clone(),
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::currentAddress`] field.
    pub fn try_current_address(&self) -> Option<u64> {
        match self {
            FormInputField::Address {
                current_address, ..
            } => Some(*current_address),
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::choices`] field.
    pub fn try_choices(&self) -> Option<Vec<String>> {
        match self {
            FormInputField::Choice { choices, .. } => Some(choices.clone()),
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::ext`] field.
    pub fn try_extension(&self) -> Option<String> {
        match self {
            Self::SaveFileName { extension, .. } => extension.clone(),
            Self::OpenFileName { extension, .. } => extension.clone(),
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::hasDefault`] field.
    pub fn try_has_default(&self) -> Option<bool> {
        match self {
            FormInputField::Label { .. } => None,
            FormInputField::Separator => None,
            FormInputField::TextLine { default, .. } => Some(default.is_some()),
            FormInputField::MultilineText { default, .. } => Some(default.is_some()),
            FormInputField::Integer { default, .. } => Some(default.is_some()),
            FormInputField::Address { default, .. } => Some(default.is_some()),
            FormInputField::Choice { default, .. } => Some(default.is_some()),
            FormInputField::OpenFileName { default, .. } => Some(default.is_some()),
            FormInputField::SaveFileName { default, .. } => Some(default.is_some()),
            FormInputField::DirectoryName { default, .. } => Some(default.is_some()),
        }
    }

    /// Mapping to the [`BNFormInputField::defaultName`] field.
    pub fn try_default_name(&self) -> Option<String> {
        match self {
            Self::SaveFileName { default_name, .. } => default_name.clone(),
            Self::DirectoryName { default_name, .. } => default_name.clone(),
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::intDefault`] field.
    pub fn try_default_int(&self) -> Option<i64> {
        match self {
            FormInputField::Integer { default, .. } => *default,
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::addressDefault`] field.
    pub fn try_default_address(&self) -> Option<u64> {
        match self {
            FormInputField::Address { default, .. } => *default,
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::stringDefault`] field.
    pub fn try_default_string(&self) -> Option<String> {
        match self {
            FormInputField::TextLine { default, .. } => default.clone(),
            FormInputField::MultilineText { default, .. } => default.clone(),
            FormInputField::OpenFileName { default, .. } => default.clone(),
            FormInputField::SaveFileName { default, .. } => default.clone(),
            FormInputField::DirectoryName { default, .. } => default.clone(),
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::indexDefault`] field.
    pub fn try_default_index(&self) -> Option<usize> {
        match self {
            FormInputField::Choice { default, .. } => *default,
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::intResult`] field.
    pub fn try_value_int(&self) -> Option<i64> {
        match self {
            FormInputField::Integer { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::addressResult`] field.
    pub fn try_value_address(&self) -> Option<u64> {
        match self {
            FormInputField::Address { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::stringResult`] field.
    pub fn try_value_string(&self) -> Option<String> {
        match self {
            FormInputField::TextLine { value, .. } => value.clone(),
            FormInputField::MultilineText { value, .. } => value.clone(),
            FormInputField::OpenFileName { value, .. } => value.clone(),
            FormInputField::SaveFileName { value, .. } => value.clone(),
            FormInputField::DirectoryName { value, .. } => value.clone(),
            _ => None,
        }
    }

    /// Mapping to the [`BNFormInputField::indexResult`] field.
    pub fn try_value_index(&self) -> Option<usize> {
        match self {
            FormInputField::Choice { value, .. } => Some(*value),
            _ => None,
        }
    }
}
