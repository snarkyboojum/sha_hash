/*

This implementation only works for SHA-512 currently. Other algorithms
may be added later on. See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
for implementation details.

The algorithm consists of two main stages:

1. Preprocessing
 - Padding
 - Parsing into m-bit blocks
 - Setting initialisation values to be used in the hash computation

2. Hash computation
 - generate message schedule
 - iteratively generate hash values using the message schedule etc

 SHA-512 details:
 - Message size < 2 ^ 128 bits (m-bits)
 - Block size (1024 bits / 16 x 64-bit words)
 - Word size 64 bits / u64
 - Message digest size (512 bits / 8 x 64 bit words)

 Big-endian byte order is used throughout.

*/

// msg should be a multiple of 1024 bits
// pad with 1 then 0s up to msg.len % 1024 - 128 - 1
fn pad_message(msg: &[u8]) -> Vec<u8> {
    let num_blocks = (msg.len() * 8 + 128 + 1) / 1024;
    let min_msg_bits = msg.len() * 8 % 1024 + 1;
    let mut num_zero_bits = 0;

    use std::cmp::Ordering;
    match min_msg_bits.cmp(&896) {
        Ordering::Less => {
            num_zero_bits = 896 - (msg.len() * 8 % 1024 + 1);
        }
        Ordering::Greater => {
            if num_blocks > 1 {
                num_zero_bits = 1024 - ((msg.len() * 8 + 1 + 128) % 1024) + 1024 * num_blocks;
            } else {
                num_zero_bits = 1024 - ((msg.len() * 8 + 1 + 128) % 1024);
            }
        }
        Ordering::Equal => {}
    }

    let buffer_size = (msg.len() * 8) + 1 + num_zero_bits + 128;

    // 128 bit representation of the length of the message
    let length_128: u128 = (msg.len() * 8) as u128;

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
    buffer.put_u128(length_128);
    buffer.to_vec()
}

// Functions to be used during the hash computation
#[allow(dead_code)]
fn rotl(n: u64, x: u64) -> u64 {
    (x << n) | (x >> (64 - n))
}
fn rotr(n: u64, x: u64) -> u64 {
    (x >> n) | (x << (64 - n))
}
fn shr(n: u64, x: u64) -> u64 {
    x >> n
}

fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn s_sigma1_512(word: u64) -> u64 {
    rotr(19, word) ^ rotr(61, word) ^ shr(6, word)
}

fn s_sigma0_512(word: u64) -> u64 {
    rotr(1, word) ^ rotr(8, word) ^ shr(7, word)
}

fn b_sigma1_512(word: u64) -> u64 {
    rotr(14, word) ^ rotr(18, word) ^ rotr(41, word)
}

fn b_sigma0_512(word: u64) -> u64 {
    rotr(28, word) ^ rotr(34, word) ^ rotr(39, word)
}

pub fn hash(msg: &[u8]) -> Option<[u64; 8]> {
    if msg.is_empty() {
        None
    } else {
        let padded_message = pad_message(msg);
        //println!("Padded message: {:#x?}", padded_message);
        //println!("Length of padded message: {} bytes", padded_message.len());

        // we only take n * 1024 bit messages
        assert_eq!((padded_message.len() * 8) % 1024, 0);

        // parse into 1024 bit blocks (128 bytes), using 64 bit words (8 bytes)
        // see 6.4.1 and 6.4.2 on p24 of
        // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
        use byteorder::{BigEndian, ByteOrder};

        let mut hashes: [u64; 8] = SHA_512_INIT;
        //println!("Initial hashes: {:#x?}", hashes);
        for (_i, block) in padded_message.chunks(128).enumerate() {
            let mut t = 0;
            let mut msg_schedule: [u64; 80] = [0u64; 80];

            // build message schedule
            for word in block.chunks(8) {
                if t < 16 {
                    msg_schedule[t] = BigEndian::read_u64(word);
                }
                t += 1;
            }
            for t in 16..80 {
                msg_schedule[t] = s_sigma1_512(msg_schedule[t - 2])
                    .wrapping_add(msg_schedule[t - 7])
                    .wrapping_add(s_sigma0_512(msg_schedule[t - 15]))
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

            for t in 0..80 {
                //print!("t={}: ", t);
                let t1 = h
                    .wrapping_add(b_sigma1_512(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(SHA_512[t])
                    .wrapping_add(msg_schedule[t]);
                let t2 = b_sigma0_512(a).wrapping_add(maj(a, b, c));

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
    fn test_sha512_hash() {
        use std::collections::HashMap;
        let mut message_hashes: HashMap<&str, [u64; 8]> = HashMap::new();
        message_hashes.insert(
            "",
            [
                0xcf83e1357eefb8bd,
                0xf1542850d66d8007,
                0xd620e4050b5715dc,
                0x83f4a921d36ce9ce,
                0x47d0d13c5d85f2b0,
                0xff8318d2877eec2f,
                0x63b931bd47417a81,
                0xa538327af927da3e,
            ],
        );
        message_hashes.insert(
            "abc",
            [
                0xddaf35a193617aba,
                0xcc417349ae204131,
                0x12e6fa4e89a97ea2,
                0x0a9eeee64b55d39a,
                0x2192992a274fc1a8,
                0x36ba3c23a3feebbd,
                0x454d4423643ce80e,
                0x2a9ac94fa54ca49f,
            ],
        );
        message_hashes.insert(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            [
                0x204a8fc6dda82f0a,
                0x0ced7beb8e08a416,
                0x57c16ef468b228a8,
                0x279be331a703c335,
                0x96fd15c13b1b07f9,
                0xaa1d3bea57789ca0,
                0x31ad85c7a71dd703,
                0x54ec631238ca3445,
            ],
        );
        message_hashes.insert(
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            [0x8e959b75dae313da, 0x8cf4f72814fc143f, 0x8f7779c6eb9f7fa1, 0x7299aeadb6889018, 0x501d289e4900f7e4, 0x331b99dec4b5433a, 0xc7d329eeb6dd2654, 0x5e96e55b874be909]
        );

        for (msg, hash) in message_hashes.iter() {
            let test_hashes = super::hash(&msg.as_bytes());

            for (i, test_hash) in test_hashes.iter().enumerate() {
                assert_eq!(hash[i], test_hash[i]);
            }
        }
    }
}

// the initial hash value consists of the following eight 64-bit words (i.e. 512 bits)
const SHA_512_INIT: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

// SHA-384, SHA-512, SHA-512/224 and SHA-512/256 use the same sequence of
// eighty constant 64-bit words
const SHA_512: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];
