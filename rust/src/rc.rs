// Copyright 2021 Vector 35 Inc.
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

use std::borrow::Borrow;
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

pub trait CoreArrayProvider {
    type Raw;
    type Context;
}

pub unsafe trait CoreOwnedArrayProvider: CoreArrayProvider {
    unsafe fn free(raw: *mut Self::Raw, count: usize, context: &Self::Context);
}

pub unsafe trait CoreArrayWrapper<'a>: CoreArrayProvider
where
    Self::Raw: 'a,
    Self::Context: 'a,
{
    type Wrapped: 'a;

    unsafe fn wrap_raw(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped;
}

pub struct Array<P: CoreOwnedArrayProvider> {
    contents: *mut P::Raw,
    count: usize,
    context: P::Context,
}

unsafe impl<P> Sync for Array<P>
where
    P: CoreOwnedArrayProvider,
    P::Context: Sync,
{
}
unsafe impl<P> Send for Array<P>
where
    P: CoreOwnedArrayProvider,
    P::Context: Send,
{
}

impl<P: CoreOwnedArrayProvider> Array<P> {
    pub(crate) unsafe fn new(raw: *mut P::Raw, count: usize, context: P::Context) -> Self {
        Self {
            contents: raw,
            count,
            context,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn into_raw_parts(self) -> (*mut P::Raw, usize) {
        let me = mem::ManuallyDrop::new(self);
        (me.contents, me.count)
    }
}

impl<'a, P: 'a + CoreArrayWrapper<'a> + CoreOwnedArrayProvider> Array<P> {
    #[inline]
    pub fn get(&'a self, index: usize) -> P::Wrapped {
        unsafe {
            let backing = slice::from_raw_parts(self.contents, self.count);
            P::wrap_raw(&backing[index], &self.context)
        }
    }

    pub fn iter(&'a self) -> ArrayIter<'a, P> {
        ArrayIter {
            it: unsafe { slice::from_raw_parts(self.contents, self.count).iter() },
            context: &self.context,
        }
    }
}

impl<'a, P: 'a + CoreArrayWrapper<'a> + CoreOwnedArrayProvider> IntoIterator for &'a Array<P> {
    type Item = P::Wrapped;
    type IntoIter = ArrayIter<'a, P>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<P: CoreOwnedArrayProvider> Drop for Array<P> {
    fn drop(&mut self) {
        unsafe {
            P::free(self.contents, self.count, &self.context);
        }
    }
}

pub struct ArrayGuard<P: CoreArrayProvider> {
    contents: *mut P::Raw,
    count: usize,
    context: P::Context,
}

unsafe impl<P> Sync for ArrayGuard<P>
where
    P: CoreArrayProvider,
    P::Context: Sync,
{
}
unsafe impl<P> Send for ArrayGuard<P>
where
    P: CoreArrayProvider,
    P::Context: Send,
{
}

impl<P: CoreArrayProvider> ArrayGuard<P> {
    pub(crate) unsafe fn new(raw: *mut P::Raw, count: usize, context: P::Context) -> Self {
        Self {
            contents: raw,
            count,
            context,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'a, P: 'a + CoreArrayWrapper<'a> + CoreArrayProvider> ArrayGuard<P> {
    #[inline]
    pub fn get(&'a self, index: usize) -> P::Wrapped {
        unsafe {
            let backing = slice::from_raw_parts(self.contents, self.count);
            P::wrap_raw(&backing[index], &self.context)
        }
    }

    pub fn iter(&'a self) -> ArrayIter<'a, P> {
        ArrayIter {
            it: unsafe { slice::from_raw_parts(self.contents, self.count).iter() },
            context: &self.context,
        }
    }
}

impl<'a, P: 'a + CoreArrayWrapper<'a> + CoreArrayProvider> IntoIterator for &'a ArrayGuard<P> {
    type Item = P::Wrapped;
    type IntoIter = ArrayIter<'a, P>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct ArrayIter<'a, P>
where
    P: 'a + CoreArrayWrapper<'a>,
{
    it: slice::Iter<'a, P::Raw>,
    context: &'a P::Context,
}

unsafe impl<'a, P> Send for ArrayIter<'a, P>
where
    P: CoreArrayWrapper<'a>,
    P::Context: Sync,
{
}

impl<'a, P> Iterator for ArrayIter<'a, P>
where
    P: 'a + CoreArrayWrapper<'a>,
{
    type Item = P::Wrapped;

    #[inline]
    fn next(&mut self) -> Option<P::Wrapped> {
        self.it
            .next()
            .map(|r| unsafe { P::wrap_raw(r, &self.context) })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.it.size_hint()
    }
}

impl<'a, P> ExactSizeIterator for ArrayIter<'a, P>
where
    P: 'a + CoreArrayWrapper<'a>,
{
    #[inline]
    fn len(&self) -> usize {
        self.it.len()
    }
}

impl<'a, P> DoubleEndedIterator for ArrayIter<'a, P>
where
    P: 'a + CoreArrayWrapper<'a>,
{
    #[inline]
    fn next_back(&mut self) -> Option<P::Wrapped> {
        self.it
            .next_back()
            .map(|r| unsafe { P::wrap_raw(r, &self.context) })
    }
}

#[cfg(feature = "rayon")]
use rayon::prelude::*;

#[cfg(feature = "rayon")]
use rayon::iter::plumbing::*;

#[cfg(feature = "rayon")]
impl<'a, P> Array<P>
where
    P: 'a + CoreArrayWrapper<'a> + CoreOwnedArrayProvider,
    P::Context: Sync,
    P::Wrapped: Send,
{
    pub fn par_iter(&'a self) -> ParArrayIter<'a, P> {
        ParArrayIter { it: self.iter() }
    }
}
#[cfg(feature = "rayon")]
pub struct ParArrayIter<'a, P>
where
    P: 'a + CoreArrayWrapper<'a>,
    ArrayIter<'a, P>: Send,
{
    it: ArrayIter<'a, P>,
}

#[cfg(feature = "rayon")]
impl<'a, P> ParallelIterator for ParArrayIter<'a, P>
where
    P: 'a + CoreArrayWrapper<'a>,
    P::Wrapped: Send,
    ArrayIter<'a, P>: Send,
{
    type Item = P::Wrapped;

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
    P: 'a + CoreArrayWrapper<'a>,
    P::Wrapped: Send,
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
    P: 'a + CoreArrayWrapper<'a>,
    ArrayIter<'a, P>: Send,
{
    it: ArrayIter<'a, P>,
}

#[cfg(feature = "rayon")]
impl<'a, P> Producer for ArrayIterProducer<'a, P>
where
    P: 'a + CoreArrayWrapper<'a>,
    ArrayIter<'a, P>: Send,
{
    type Item = P::Wrapped;
    type IntoIter = ArrayIter<'a, P>;

    fn into_iter(self) -> ArrayIter<'a, P> {
        self.it
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        let (l, r) = self.it.it.as_slice().split_at(index);

        (
            Self {
                it: ArrayIter {
                    it: l.iter(),
                    context: self.it.context,
                },
            },
            Self {
                it: ArrayIter {
                    it: r.iter(),
                    context: self.it.context,
                },
            },
        )
    }
}
