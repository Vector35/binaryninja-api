use crate::architecture::{Architecture, CoreArchitecture};
use crate::callingconvention::CallingConvention;
use crate::rc::{Ref, RefCountable};
use crate::types::Type;
use binaryninjacore_sys::{
    BNBoolWithConfidence, BNCallingConventionWithConfidence, BNGetCallingConventionArchitecture,
    BNOffsetWithConfidence, BNTypeWithConfidence,
};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};

/// The minimum allowed confidence of any given [`Type`].
pub const MIN_CONFIDENCE: u8 = u8::MIN;

/// The maximum allowed confidence of any given [`Type`].
pub const MAX_CONFIDENCE: u8 = u8::MAX;

/// Compatible with the `BNType*WithConfidence` types
pub struct Conf<T> {
    pub contents: T,
    pub confidence: u8,
}

pub trait ConfMergable<T, O> {
    type Result;
    /// Merge two confidence types' values depending on whichever has higher confidence
    /// In the event of a tie, the LHS (caller's) value is used.
    fn merge(self, other: O) -> Self::Result;
}

impl<T> Conf<T> {
    pub fn new(contents: T, confidence: u8) -> Self {
        Self {
            contents,
            confidence,
        }
    }

    pub fn map<U, F>(self, f: F) -> Conf<U>
    where
        F: FnOnce(T) -> U,
    {
        Conf::new(f(self.contents), self.confidence)
    }

    pub fn as_ref<U>(&self) -> Conf<&U>
    where
        T: AsRef<U>,
    {
        Conf::new(self.contents.as_ref(), self.confidence)
    }
}

/// Returns best value or LHS on tie
///
/// `Conf<T>` + `Conf<T>` → `Conf<T>`
impl<T> ConfMergable<T, Conf<T>> for Conf<T> {
    type Result = Conf<T>;
    fn merge(self, other: Conf<T>) -> Conf<T> {
        if other.confidence > self.confidence {
            other
        } else {
            self
        }
    }
}

/// Returns LHS if RHS is None
///
/// `Conf<T>` + `Option<Conf<T>>` → `Conf<T>`
impl<T> ConfMergable<T, Option<Conf<T>>> for Conf<T> {
    type Result = Conf<T>;
    fn merge(self, other: Option<Conf<T>>) -> Conf<T> {
        match other {
            Some(c @ Conf { confidence, .. }) if confidence > self.confidence => c,
            _ => self,
        }
    }
}

/// Returns RHS if LHS is None
///
/// `Option<Conf<T>>` + `Conf<T>` → `Conf<T>`
impl<T> ConfMergable<T, Conf<T>> for Option<Conf<T>> {
    type Result = Conf<T>;
    fn merge(self, other: Conf<T>) -> Conf<T> {
        match self {
            Some(c @ Conf { confidence, .. }) if confidence >= other.confidence => c,
            _ => other,
        }
    }
}

/// Returns best non-None value or None
///
/// `Option<Conf<T>>` + `Option<Conf<T>>` → `Option<Conf<T>>`
impl<T> ConfMergable<T, Option<Conf<T>>> for Option<Conf<T>> {
    type Result = Option<Conf<T>>;
    fn merge(self, other: Option<Conf<T>>) -> Option<Conf<T>> {
        match (self, other) {
            (
                Some(
                    this @ Conf {
                        confidence: this_confidence,
                        ..
                    },
                ),
                Some(
                    other @ Conf {
                        confidence: other_confidence,
                        ..
                    },
                ),
            ) => {
                if this_confidence >= other_confidence {
                    Some(this)
                } else {
                    Some(other)
                }
            }
            (None, Some(c)) => Some(c),
            (Some(c), None) => Some(c),
            (None, None) => None,
        }
    }
}

impl<T: Debug> Debug for Conf<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} ({} confidence)", self.contents, self.confidence)
    }
}

impl<T: Display> Display for Conf<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} confidence)", self.contents, self.confidence)
    }
}

impl<T: PartialEq> PartialEq for Conf<T> {
    fn eq(&self, other: &Self) -> bool {
        self.contents.eq(&other.contents)
    }
}

impl<T: Eq> Eq for Conf<T> {}

impl<T: Hash> Hash for Conf<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.contents.hash(state);
    }
}

impl<'a, T> From<&'a Conf<T>> for Conf<&'a T> {
    fn from(c: &'a Conf<T>) -> Self {
        Conf::new(&c.contents, c.confidence)
    }
}

impl<'a, T: RefCountable> From<&'a Conf<Ref<T>>> for Conf<&'a T> {
    fn from(c: &'a Conf<Ref<T>>) -> Self {
        Conf::new(c.contents.as_ref(), c.confidence)
    }
}

impl<'a, T: RefCountable> From<&'a Ref<T>> for Conf<&'a T> {
    fn from(r: &'a Ref<T>) -> Self {
        r.as_ref().into()
    }
}

impl<T: Clone> Clone for Conf<T> {
    fn clone(&self) -> Self {
        Self {
            contents: self.contents.clone(),
            confidence: self.confidence,
        }
    }
}

impl<T: Copy> Copy for Conf<T> {}

impl<T> From<T> for Conf<T> {
    fn from(contents: T) -> Self {
        Self::new(contents, MAX_CONFIDENCE)
    }
}

impl From<BNTypeWithConfidence> for Conf<Ref<Type>> {
    fn from(type_with_confidence: BNTypeWithConfidence) -> Self {
        Self::new(
            unsafe { Type::ref_from_raw(type_with_confidence.type_) },
            type_with_confidence.confidence,
        )
    }
}

impl From<BNBoolWithConfidence> for Conf<bool> {
    fn from(bool_with_confidence: BNBoolWithConfidence) -> Self {
        Self::new(bool_with_confidence.value, bool_with_confidence.confidence)
    }
}

impl From<BNCallingConventionWithConfidence> for Conf<Ref<CallingConvention<CoreArchitecture>>> {
    fn from(cc_with_confidence: BNCallingConventionWithConfidence) -> Self {
        Self::new(
            unsafe {
                CallingConvention::ref_from_raw(
                    cc_with_confidence.convention,
                    CoreArchitecture::from_raw(BNGetCallingConventionArchitecture(
                        cc_with_confidence.convention,
                    )),
                )
            },
            cc_with_confidence.confidence,
        )
    }
}

impl From<BNOffsetWithConfidence> for Conf<i64> {
    fn from(offset_with_confidence: BNOffsetWithConfidence) -> Self {
        Self::new(
            offset_with_confidence.value,
            offset_with_confidence.confidence,
        )
    }
}

impl From<Conf<Ref<Type>>> for BNTypeWithConfidence {
    fn from(conf: Conf<Ref<Type>>) -> Self {
        Self {
            type_: conf.contents.handle,
            confidence: conf.confidence,
        }
    }
}

impl From<Conf<&Type>> for BNTypeWithConfidence {
    fn from(conf: Conf<&Type>) -> Self {
        Self {
            type_: conf.contents.handle,
            confidence: conf.confidence,
        }
    }
}

impl From<Conf<bool>> for BNBoolWithConfidence {
    fn from(conf: Conf<bool>) -> Self {
        Self {
            value: conf.contents,
            confidence: conf.confidence,
        }
    }
}

impl<A: Architecture> From<Conf<&CallingConvention<A>>> for BNCallingConventionWithConfidence {
    fn from(conf: Conf<&CallingConvention<A>>) -> Self {
        Self {
            convention: conf.contents.handle,
            confidence: conf.confidence,
        }
    }
}

impl From<Conf<i64>> for BNOffsetWithConfidence {
    fn from(conf: Conf<i64>) -> Self {
        Self {
            value: conf.contents,
            confidence: conf.confidence,
        }
    }
}
