use sha_hash::{sha256, sha512};

fn main() {
    println!("Welcome to the SHA-2 implementation in Rust!");

    let msg = "Look again at that dot. That's here. That's home. That's us. On it everyone you love, everyone you know, \
                 everyone you ever heard of, every human being who ever was, lived out their lives. -Carl Sagan";
    println!("Message is: {}", msg);

    let hashes_256 = sha256::hash(&msg.as_bytes());
    println!("SHA-256 hash of message is: {:#x?}", hashes_256.unwrap());

    let hashes_512 = sha512::hash(&msg.as_bytes());
    println!("SHA-512 hash of message is: {:#x?}", hashes_512.unwrap());
}
