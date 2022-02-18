use std::{fmt, backtrace::Backtrace, error::Error};

#[allow(dead_code)] // it's used in `Debug` which is used in `Display` which is used to show the error
#[derive(Debug)]
pub struct BNError {
    repr: BNErrorRepr,
    backtrace: Option<Backtrace>,
    cause: Option<Box<dyn Error>>,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum BNErrorRepr {
    Generic(String),
    APIError { api_function: String, other_info: Option<String>},
    IOError,
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

pub fn bytes_error_repr(r: &[u8]) -> String {
    String::from_utf8_lossy(r).to_string()
}

impl fmt::Display for BNError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl BNError {
    pub fn generic(msg: &str) -> BNError {
        BNError {
            repr: BNErrorRepr::Generic(String::from(msg)),
            backtrace: Some(Backtrace::capture()),
            cause: None
        }
    }
    pub fn api_error(func: &str, other_info: Option<&str>) -> BNError {
        BNError {
            repr: BNErrorRepr::APIError{
                api_function: String::from(func),
                other_info: other_info.map(String::from),
            },
            backtrace: Some(Backtrace::capture()),
            cause: None
        }
    }
}
impl Error for BNError {
    fn backtrace(&self) -> Option<&Backtrace> {
        self.backtrace.as_ref()
    }
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            Some(ex) => Some(ex.as_ref()),
            None => None,
        }
    }
}