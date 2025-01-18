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

    pub unsafe extern "C" fn cb_execute(ctx: *mut c_void, progress: usize, total: usize) -> bool {
        if ctx.is_null() {
            return true;
        }
        let executor: *mut Self = ctx as *mut Self;
        (*executor).execute(progress, total)
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
