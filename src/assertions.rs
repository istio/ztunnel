// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Below helper functions are used to help make about the size of types.
// There are some compile time ways to do this, but they don't work in the way we need for the most part;
// analyzing the size of Futures which we don't have explicit declarations for.
// Future size is determined by the max required stack size for the async function. This means deeply
// branched code can create huge Future's, leading to high per-connection memory usage in ztunnel.
// Debugging these usages can be done by `RUSTFLAGS=-Zprint-type-sizes cargo +nightly build -j 1`,
// or by logging with the functions below.

#[cfg(all(any(test, feature = "testing"), debug_assertions))]
pub fn size_between_ref<T>(min: usize, max: usize, t: &T) {
    let size = std::mem::size_of_val(t);
    if size < min || size > max {
        // If it is too small: that is good, we just want to update the assertion to be more aggressive
        // If it is too big: that is bad. We may need to increase the limit, or consider refactors.
        panic!(
            "type {} size is unexpected, wanted {min}..{max}, got {size}",
            std::any::type_name::<T>(),
        )
    }
    tracing::trace!(
        "type {} size is within expectations, wanted {min}..{max}, got {size}",
        std::any::type_name::<T>(),
    )
}

#[cfg(not(all(any(test, feature = "testing"), debug_assertions)))]
pub fn size_between_ref<T>(_min: usize, _max: usize, _t: &T) {}

#[inline(always)]
pub fn size_between<T>(min: usize, max: usize, t: T) -> T {
    size_between_ref(min, max, &t);
    t
}
