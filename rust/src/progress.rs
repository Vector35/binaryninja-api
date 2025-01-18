use std::ffi::c_void;

pub struct ProgressExecutor {
    func: Box<dyn Fn(usize, usize) -> bool>,
}

impl ProgressExecutor {
    pub fn new<F: Fn(usize, usize) -> bool + 'static>(func: F) -> Self {
        Self {
            func: Box::new(func),
        }
    }

    /// Leak the executor and return an opaque pointer.
    pub fn into_raw_context(self) -> *mut c_void {
        Box::into_raw(Box::new(self)) as *mut c_void
    }

    pub unsafe extern "C" fn cb_execute(ctx: *mut c_void, progress: usize, total: usize) -> bool {
        if ctx.is_null() {
            return true;
        }
        let f: Box<Self> = Box::from_raw(ctx as *mut Self);
        f.execute(progress, total)
    }

    pub fn execute(&self, progress: usize, total: usize) -> bool {
        (self.func)(progress, total)
    }
}

impl<F: Fn(usize, usize) -> bool + 'static> From<F> for ProgressExecutor {
    fn from(func: F) -> Self {
        Self::new(func)
    }
}

impl Default for ProgressExecutor {
    fn default() -> Self {
        Self::new(|_, _| true)
    }
}
