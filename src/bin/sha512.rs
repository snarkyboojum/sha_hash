extern crate sha_hash;
use sha_hash::sha512_hash;

fn main() {
    println!("Welcome to the AES-512 implementation in Rust!");

    let msg = "Look again at that dot. That's here. That's home. That's us. On it everyone you love, everyone you know, \
                 everyone you ever heard of, every human being who ever was, lived out their lives. -Carl Sagan";
    println!("Message is: {}", msg);

    let hashes = sha512_hash(&msg.as_bytes());
    println!("Hash of message is: {:#x?}", hashes.unwrap());
}
