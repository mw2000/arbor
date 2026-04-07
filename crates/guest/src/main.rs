#![cfg_attr(feature = "guest", no_std)]
#![cfg_attr(feature = "guest", no_main)]

#[allow(unused_imports)]
use arbor_guest::*;

#[cfg(not(feature = "guest"))]
fn main() {}
