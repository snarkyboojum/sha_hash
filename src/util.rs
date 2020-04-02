// TODO: how do we make these utility functions available to other
// modules within the *same* crate - without making them globally public
//
// Functions to be used during the hash computation

pub fn rotl64(n: u64, x: u64) -> u64 {
    (x << n) | (x >> (64 - n))
}
pub fn rotr64(n: u64, x: u64) -> u64 {
    (x >> n) | (x << (64 - n))
}
pub fn shr64(n: u64, x: u64) -> u64 {
    x >> n
}

pub fn rotl32(n: u32, x: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}
pub fn rotr32(n: u32, x: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}
pub fn shr32(n: u32, x: u32) -> u32 {
    x >> n
}
