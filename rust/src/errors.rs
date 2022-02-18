use std::{fmt, backtrace::Backtrace, error::Error, ffi::FromBytesWithNulError};

#[allow(dead_code)] // it's used in `Debug` which is used in `Display` which is used to show the error
#[derive(Debug)]
pub struct BNError {
    repr: BNErrorRepr,
    backtrace: Option<Backtrace>,
}

#[derive(Debug)]
pub enum BNErrorRepr {
    Generic(String),
    APIError { api_function: String, other_info: Option<String>},
    IOError { cause: std::io::Error },
    FFIStrDecodeError { cause: FromBytesWithNulError }
}

macro_rules! bn_api_error {
    ($func:tt) => {
        BNError::api_error(stringify!($func), None)
    };
    ($func:tt, $extra:expr) => {
        BNError::api_error(stringify!($func), Some($extra))
    };
}
pub(crate) use bn_api_error;

pub type BNResult<R> = Result<R, BNError>;

pub struct Utf8Display<'a>(pub &'a dyn AsRef<[u8]>);
impl<'a> std::fmt::Debug for Utf8Display<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(self.0.as_ref()).to_string())
    }
}
impl<'a> std::fmt::Display for Utf8Display<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as std::fmt::Debug>::fmt(self, f)
    }
}

impl fmt::Display for BNError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl BNError {
    #[inline(always)]
    pub fn generic(msg: &str) -> BNError {
        BNError {
            repr: BNErrorRepr::Generic(String::from(msg)),
            backtrace: Some(Backtrace::capture()),
        }
    }
    #[inline(always)]
    pub fn api_error(func: &str, other_info: Option<&str>) -> BNError {
        BNError {
            repr: BNErrorRepr::APIError{
                api_function: String::from(func),
                other_info: other_info.map(String::from),
            },
            backtrace: Some(Backtrace::capture()),
        }
    }
}

impl Error for BNError {
    fn backtrace(&self) -> Option<&Backtrace> {
        // if the cause has a backtrace use that, otherwise use ours if possible
        self.source()
            .and_then(Error::backtrace)
            .or(self.backtrace.as_ref())
    }
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.repr {
            BNErrorRepr::IOError { cause } => Some(cause),
            _ => None,
        }
    }
}

impl From<FromBytesWithNulError> for BNError {
    fn from(e: FromBytesWithNulError) -> Self {
        BNError {
            repr: BNErrorRepr::FFIStrDecodeError { cause: e },
            backtrace: None // we rely on the `cause` Backtrace
        }
    }
}
impl From<std::io::Error> for BNError {
    fn from(e: std::io::Error) -> Self {
        BNError {
            repr: BNErrorRepr::IOError { cause: e },
            backtrace: None // we rely on the `cause` Backtrace
        }
    }
}