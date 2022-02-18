use std::{fmt, backtrace::Backtrace, error::Error, ffi::FromBytesWithNulError};

#[allow(dead_code)] // it's used in `Debug` which is used in `Display` which is used to show the error
pub struct BNError {
    repr: BNErrorRepr,
    backtrace: Option<Backtrace>,
    cause: Option<Box<dyn Error>>,
    context: Vec<String>,
}
impl std::fmt::Display for BNError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\nEncountered error: {:?}\n", self.repr)?;
        if self.context.len() > 0 {
            writeln!(f, "Contextual information: ")?;
            for m in &self.context {
                writeln!(f, " - {}", m)?;
            }
        }

        if let Some(bt) = &self.backtrace {
            writeln!(f, "Backtrace: ")?;
            writeln!(f, "{:#}", bt)?;
        }
        if let Some(cause) = self.source() {
            writeln!(f, "Caused by: {:?}", cause)?;
        }

        Ok(())
    }
}

impl fmt::Debug for BNError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Self as fmt::Display>::fmt(self, f)
    }
}

#[derive(Debug)]
pub enum BNErrorRepr {
    Generic,
    APIError { api_function: String, other_info: Option<String>},
    Chained,
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

impl BNError {
    #[inline(always)]
    pub fn generic(context: &str) -> BNError {
        BNError {
            repr: BNErrorRepr::Generic,
            backtrace: Some(Backtrace::capture()),
            cause: None,
            context: vec![String::from(context)],
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
            cause: None,
            context: Default::default(),
        }
    }
    pub fn contextualize(mut self, msg: &str) -> Self{
        self.context.push(String::from(msg));
        self
    }
    pub fn caused_by<T: Error + 'static>(mut self, e: T) -> Self {
        assert!(self.cause.take().is_none());
        self.cause = Some(Box::new(e));
        self
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
        match &self.cause {
            Some(x) => Some(x.as_ref()),
            _ => None,
        }
    }
}

impl From<FromBytesWithNulError> for BNError {
    fn from(e: FromBytesWithNulError) -> Self {
        BNError {
            repr: BNErrorRepr::Chained,
            backtrace: Some(Backtrace::capture()),
            cause: Some(Box::new(e)),
            context: Default::default()
        }
    }
}
impl From<std::io::Error> for BNError {
    fn from(e: std::io::Error) -> Self {
        BNError {
            repr: BNErrorRepr::Chained,
            backtrace: Some(Backtrace::capture()),
            cause: Some(Box::new(e)),
            context: Default::default()
        }
    }
}