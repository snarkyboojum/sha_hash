use crate::util::*;

/*

This is the SHA-256 implementation.
See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
for implementation details.

The algorithm consists of two main stages:

1. Preprocessing
 - Padding
 - Parsing into m-bit blocks
 - Setting initialisation values to be used in the hash computation

2. Hash computation
 - generate message schedule
 - iteratively generate hash values using the message schedule etc

 SHA-256 details:
 - Message size < 2 ^ 64 bits (m-bits)
 - Block size (512 bits / 16 x 32-bit words)
 - Word size 32 bits / u32
 - Message digest size (256 bits / 8 x 32 bit words)

 Big-endian byte order is used throughout.

*/

// msg should be a multiple of 512 bits
// pad with 1 then 0s up to msg.len % 512 - 64 - 1
fn pad_message(msg: &[u8]) -> Vec<u8> {
    let num_blocks = (msg.len() * 8 + 64 + 1) / 512;
    let min_msg_bits = msg.len() * 8 % 512 + 1;
    let mut num_zero_bits = 0;

    use std::cmp::Ordering;
    match min_msg_bits.cmp(&448) {
        Ordering::Less => {
            num_zero_bits = 448 - (msg.len() * 8 % 512 + 1);
        }
        Ordering::Greater => {
            if num_blocks > 1 {
                num_zero_bits = 512 - ((msg.len() * 8 + 1 + 64) % 512) + 512 * num_blocks;
            } else {
                num_zero_bits = 512 - ((msg.len() * 8 + 1 + 64) % 512);
            }
        }
        Ordering::Equal => {}
    }

    let buffer_size = (msg.len() * 8) + 1 + num_zero_bits + 64;

    // 64 bit representation of the length of the message
    let length_64: u64 = (msg.len() * 8) as u64;

    use bytes::{BufMut, BytesMut};
    let mut buffer = BytesMut::with_capacity(buffer_size / 8);
    buffer.put(msg);
    if num_zero_bits > 0 {
        buffer.put_u8(0x80);
        for _ in 0..(num_zero_bits / 8) {
            buffer.put_u8(0x00);
        }
    } else {
        // TODO: not sure how to handle this
    }
    buffer.put_u64(length_64);
    buffer.to_vec()
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn s_sigma1_256(word: u32) -> u32 {
    rotr32(17, word) ^ rotr32(19, word) ^ shr32(10, word)
}

fn s_sigma0_256(word: u32) -> u32 {
    rotr32(7, word) ^ rotr32(18, word) ^ shr32(3, word)
}

fn b_sigma1_256(word: u32) -> u32 {
    rotr32(6, word) ^ rotr32(11, word) ^ rotr32(25, word)
}

fn b_sigma0_256(word: u32) -> u32 {
    rotr32(2, word) ^ rotr32(13, word) ^ rotr32(22, word)
}

pub fn hash(msg: &[u8]) -> Option<[u32; 8]> {
    if msg.is_empty() {
        None
    } else {
        let padded_message = pad_message(msg);
        // println!("Padded message: {:#x?}", padded_message);
        // println!("Length of padded message: {} bytes", padded_message.len());

        // we only take n * 512 bit messages
        assert_eq!((padded_message.len() * 8) % 512, 0);

        // parse into 512 bit blocks (64 bytes), using 32 bit words (4 bytes)
        // see 6.4.1 and 6.4.2 on p24 of
        // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
        use byteorder::{BigEndian, ByteOrder};

        let mut hashes = SHA_256_INIT;
        //println!("Initial hashes: {:#x?}", hashes);
        for (_i, block) in padded_message.chunks(64).enumerate() {
            let mut t = 0;
            let mut msg_schedule: [u32; 64] = [0u32; 64];

            // build message schedule
            for word in block.chunks(4) {
                if t < 16 {
                    msg_schedule[t] = BigEndian::read_u32(word);
                }
                t += 1;
            }
            for t in 16..64 {
                msg_schedule[t] = s_sigma1_256(msg_schedule[t - 2])
                    .wrapping_add(msg_schedule[t - 7])
                    .wrapping_add(s_sigma0_256(msg_schedule[t - 15]))
                    .wrapping_add(msg_schedule[t - 16]);
            }

            /*
            println!("Message schedule for block: {}", i);
            for m in msg_schedule.iter() {
                print!("{:#x?} ", m);
            }
            println!("");
            */

            let mut a = hashes[0];
            let mut b = hashes[1];
            let mut c = hashes[2];
            let mut d = hashes[3];
            let mut e = hashes[4];
            let mut f = hashes[5];
            let mut g = hashes[6];
            let mut h = hashes[7];

            for t in 0..64 {
                //print!("t={}: ", t);
                let t1 = h
                    .wrapping_add(b_sigma1_256(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(SHA_256[t])
                    .wrapping_add(msg_schedule[t]);
                let t2 = b_sigma0_256(a).wrapping_add(maj(a, b, c));

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
                /*
                print!(
                    "A: {:#x?} B: {:#x?} C: {:#x?} D: {:#x?} E: {:#x?} F: {:#x?} G: {:#x?} H: {:#x?}",
                    a, b, c, d, e, f, g, h
                );
                println!("");
                */
            }

            hashes[0] = hashes[0].wrapping_add(a);
            hashes[1] = hashes[1].wrapping_add(b);
            hashes[2] = hashes[2].wrapping_add(c);
            hashes[3] = hashes[3].wrapping_add(d);
            hashes[4] = hashes[4].wrapping_add(e);
            hashes[5] = hashes[5].wrapping_add(f);
            hashes[6] = hashes[6].wrapping_add(g);
            hashes[7] = hashes[7].wrapping_add(h);
        }

        Some(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        use std::collections::HashMap;
        let mut message_hashes: HashMap<&str, [u32; 8]> = HashMap::new();
        message_hashes.insert(
            "",
            [
                0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b,
                0x7852b855,
            ],
        );
        message_hashes.insert(
            "abc",
            [
                0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
                0xf20015ad,
            ],
        );
        message_hashes.insert(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            [
                0x248d6a61, 0xd20638b8, 0xe5c02693, 0x0c3e6039, 0xa33ce459, 0x64ff2167, 0xf6ecedd4,
                0x19db06c1,
            ],
        );
        message_hashes.insert(
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            [0xcf5b16a7, 0x78af8380, 0x036ce59e, 0x7b049237, 0x0b249b11, 0xe8f07a51, 0xafac4503, 0x7afee9d1,]
        );

        // TODO: why do I need to call super::hash here?
        for (msg, hash) in message_hashes.iter() {
            let test_hashes = super::hash(&msg.as_bytes());

            for (i, test_hash) in test_hashes.iter().enumerate() {
                println!("Test {}", i);
                assert_eq!(hash[i], test_hash[i]);
            }
        }
    }
}

// the initial hash value consists of the following eight 64-bit words (i.e. 512 bits)
const SHA_256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// SHA-384, SHA-512, SHA-512/224 and SHA-512/256 use the same sequence of
// eighty constant 64-bit words
const SHA_256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
