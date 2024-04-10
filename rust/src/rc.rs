// Copyright 2021-2024 Vector 35 Inc.
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

//! Reference counting for core Binary Ninja objects.

use std::borrow::Borrow;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::ptr;
use std::slice;

// RefCountable provides an abstraction over the various
// core-allocated refcounted resources.
//
// It is important that consumers don't acquire ownership
// of a `RefCountable` object directly -- they should only
// ever get their hands on a `Ref<T>` or `&T`, otherwise it
// would be possible for the allocation in the core to
// be trivially leaked, as `T` does not have the `Drop` impl
//
// `T` does not have the `Drop` impl in order to allow more
// efficient handling of core owned objects we receive pointers
// to in callbacks
pub unsafe trait RefCountable: ToOwned<Owned = Ref<Self>> + Sized {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self>;
    unsafe fn dec_ref(handle: &Self);
}

// Represents an 'owned' reference tracked by the core
// that we are responsible for cleaning up once we're
// done with the encapsulated value.
pub struct Ref<T: RefCountable> {
    contents: T,
}

impl<T: RefCountable> Ref<T> {
    /// Safety: You need to make sure wherever you got the contents from incremented the ref count already. Anywhere the core passes out an object to the API does this.
    pub(crate) unsafe fn new(contents: T) -> Self {
        Self { contents }
    }

    pub(crate) unsafe fn into_raw(obj: Self) -> T {
        let res = ptr::read(&obj.contents);

        mem::forget(obj);

        res
    }
}

impl<T: RefCountable> AsRef<T> for Ref<T> {
    fn as_ref(&self) -> &T {
        &self.contents
    }
}

impl<T: RefCountable> Deref for Ref<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.contents
    }
}

impl<T: RefCountable> DerefMut for Ref<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.contents
    }
}

impl<T: RefCountable> Borrow<T> for Ref<T> {
    fn borrow(&self) -> &T {
        &self.contents
    }
}

impl<T: RefCountable> Drop for Ref<T> {
    fn drop(&mut self) {
        unsafe {
            RefCountable::dec_ref(&self.contents);
        }
    }
}

impl<T: RefCountable> Clone for Ref<T> {
    fn clone(&self) -> Self {
        unsafe { RefCountable::inc_ref(&self.contents) }
    }
}

impl<T: RefCountable + Display> Display for Ref<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.contents.fmt(f)
    }
}

impl<T: RefCountable + Debug> Debug for Ref<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.contents.fmt(f)
    }
}

impl<T: RefCountable + PartialEq> PartialEq for Ref<T> {
    fn eq(&self, other: &Self) -> bool {
        self.contents.eq(&other.contents)
    }
}

impl<T: RefCountable + Eq> Eq for Ref<T> {}

impl<T: RefCountable + Hash> Hash for Ref<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.contents.hash(state);
    }
}

// Guard provides access to a core-allocated resource whose
// reference is held indirectly (e.g. a core-allocated array
// of raw `*mut BNRawT`).
//
// This wrapper is necessary because `binja-rs` wrappers around
// core objects can be bigger than the raw pointer to the core
// object. This lets us create the full wrapper object and ensure
// that it does not outlive the core-allocated array (or similar)
// that our object came from.
pub struct Guard<'a, T> {
    contents: T,
    _guard: PhantomData<&'a ()>,
}

impl<'a, T> Guard<'a, T> {
    pub(crate) unsafe fn new<O: 'a>(contents: T, _owner: &O) -> Self {
        Self {
            contents,
            _guard: PhantomData,
        }
    }
}

impl<'a, T> Guard<'a, T>
where
    T: RefCountable,
{
    #[allow(clippy::should_implement_trait)] // This _is_ out own (lite) version of that trait
    pub fn clone(&self) -> Ref<T> {
        unsafe { <T as RefCountable>::inc_ref(&self.contents) }
    }
}

impl<'a, T> AsRef<T> for Guard<'a, T> {
    fn as_ref(&self) -> &T {
        &self.contents
    }
}

impl<'a, T> Deref for Guard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.contents
    }
}

impl<'a, T> DerefMut for Guard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.contents
    }
}

impl<'a, T> Borrow<T> for Guard<'a, T> {
    fn borrow(&self) -> &T {
        &self.contents
    }
}

pub trait ArrayProvider: Sized {
    type Raw: Sized;
    type Wrapped<'a>: Sized
    where
        Self: 'a;

    fn raw_parts(&self) -> (*mut Self::Raw, usize);
    unsafe fn wrap_raw<'a>(&'a self, raw: &'a Self::Raw) -> Self::Wrapped<'a>;

    fn into_raw_parts(self) -> (*mut Self::Raw, usize) {
        let me = mem::ManuallyDrop::new(self);
        me.raw_parts()
    }

    fn as_raw_slice(&self) -> &[Self::Raw] {
        let (data, len) = self.raw_parts();
        unsafe { slice::from_raw_parts(data, len) }
    }

    unsafe fn get_raw(&self, index: usize) -> Option<&Self::Raw> {
        self.as_raw_slice().get(index)
    }

    #[inline]
    fn len(&self) -> usize {
        self.raw_parts().1
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    fn get(&self, index: usize) -> Self::Wrapped<'_> {
        unsafe { self.get_raw(index).map(|x| self.wrap_raw(x)).unwrap() }
    }

    fn iter(&self) -> ArrayIter<Self> {
        ArrayIter {
            it: 0..self.len(),
            array: self,
        }
    }
}

pub struct Array<P: CoreArrayProvider> {
    contents: *mut P::Raw,
    count: usize,
}

pub trait CoreArrayProvider: Sized {
    type Raw: Sized;
    type Wrapped<'a>: Sized
    where
        Self: 'a;

    unsafe fn free(contents: *mut Self::Raw, count: usize);
    unsafe fn wrap_raw(raw: &Self::Raw) -> Self::Wrapped<'_>;
}

unsafe impl<P> Sync for Array<P> where P: CoreArrayProvider {}
unsafe impl<P> Send for Array<P> where P: CoreArrayProvider {}

impl<P: CoreArrayProvider> Array<P> {
    pub(crate) unsafe fn new(contents: *mut P::Raw, count: usize) -> Self {
        Self { contents, count }
    }
}

impl<P: CoreArrayProvider> Drop for Array<P> {
    fn drop(&mut self) {
        unsafe { P::free(self.contents, self.count) }
    }
}

impl<P: CoreArrayProvider> ArrayProvider for Array<P> {
    type Raw = P::Raw;
    type Wrapped<'a> = P::Wrapped<'a> where P: 'a;
    fn raw_parts(&self) -> (*mut Self::Raw, usize) {
        (self.contents, self.count)
    }
    unsafe fn wrap_raw<'a>(&'a self, raw: &'a Self::Raw) -> Self::Wrapped<'a> {
        P::wrap_raw(raw)
    }
}

impl<'a, P: CoreArrayProvider> IntoIterator for &'a Array<P> {
    type IntoIter = ArrayIter<'a, Array<P>>;
    type Item = <Array<P> as ArrayProvider>::Wrapped<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct ArrayIter<'a, P> {
    it: core::ops::Range<usize>,
    array: &'a P,
}

impl<'a, P: ArrayProvider> ArrayIter<'a, P> {
    fn map_index(&self, i: usize) -> Option<P::Wrapped<'a>> {
        unsafe { self.array.get_raw(i).map(|raw| self.array.wrap_raw(raw)) }
    }
    #[cfg(feature = "rayon")]
    fn split_at(self, index: usize) -> (Self, Self) {
        let Self { it, array } = self;
        assert!(it.contains(&index));
        let l = it.start..index;
        let r = index..it.end;
        (Self { it: l, array }, Self { it: r, array })
    }
}

impl<'a, P: ArrayProvider> Iterator for ArrayIter<'a, P> {
    type Item = P::Wrapped<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.it.next().and_then(|i| self.map_index(i))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.it.size_hint()
    }
}

impl<'a, P: ArrayProvider> ExactSizeIterator for ArrayIter<'a, P> {
    #[inline]
    fn len(&self) -> usize {
        self.it.len()
    }
}

impl<'a, P: ArrayProvider> DoubleEndedIterator for ArrayIter<'a, P> {
    #[inline]
    fn next_back(&mut self) -> Option<P::Wrapped<'a>> {
        self.it.next_back().and_then(|i| self.map_index(i))
    }
}

#[cfg(feature = "rayon")]
use rayon::prelude::*;

#[cfg(feature = "rayon")]
use rayon::iter::plumbing::*;

#[cfg(feature = "rayon")]
pub trait ParIter<P: ArrayProvider + Sync> {
    fn par_iter(&self) -> ParArrayIter<P>;
}
#[cfg(feature = "rayon")]
impl<'a, P> ParIter<P> for P
where
    P: ArrayProvider + Sync + 'a,
    P::Wrapped<'a>: Send,
{
    fn par_iter(&self) -> ParArrayIter<'_, P> {
        ParArrayIter { it: self.iter() }
    }
}
#[cfg(feature = "rayon")]
pub struct ParArrayIter<'a, P>
where
    P: ArrayProvider,
    ArrayIter<'a, P>: Send,
{
    it: ArrayIter<'a, P>,
}

#[cfg(feature = "rayon")]
impl<'a, P> ParallelIterator for ParArrayIter<'a, P>
where
    P: ArrayProvider,
    P::Wrapped<'a>: Send,
    ArrayIter<'a, P>: Send,
{
    type Item = P::Wrapped<'a>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        bridge(self, consumer)
    }

    fn opt_len(&self) -> Option<usize> {
        Some(self.it.len())
    }
}

#[cfg(feature = "rayon")]
impl<'a, P> IndexedParallelIterator for ParArrayIter<'a, P>
where
    P: ArrayProvider,
    P::Wrapped<'a>: Send,
    ArrayIter<'a, P>: Send,
{
    fn drive<C>(self, consumer: C) -> C::Result
    where
        C: Consumer<Self::Item>,
    {
        bridge(self, consumer)
    }

    fn len(&self) -> usize {
        self.it.len()
    }

    fn with_producer<CB>(self, callback: CB) -> CB::Output
    where
        CB: ProducerCallback<Self::Item>,
    {
        callback.callback(ArrayIterProducer { it: self.it })
    }
}

#[cfg(feature = "rayon")]
struct ArrayIterProducer<'a, P>
where
    P: ArrayProvider,
    ArrayIter<'a, P>: Send,
{
    it: ArrayIter<'a, P>,
}

#[cfg(feature = "rayon")]
impl<'a, P> Producer for ArrayIterProducer<'a, P>
where
    P: ArrayProvider,
    ArrayIter<'a, P>: Send,
{
    type Item = P::Wrapped<'a>;
    type IntoIter = ArrayIter<'a, P>;

    fn into_iter(self) -> ArrayIter<'a, P> {
        self.it
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        let (l, r) = self.it.split_at(index);
        (Self { it: l }, Self { it: r })
    }
}
