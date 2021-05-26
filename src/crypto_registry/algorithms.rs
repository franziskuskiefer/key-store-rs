pub const SHA1: &str = "SHA-1";
pub const SHA2_224: &str = "SHA-224";
pub const SHA2_256: &str = "SHA-256";
pub const SHA2_384: &str = "SHA-384";
pub const SHA2_512: &str = "SHA-512";
pub const SHA3_224: &str = "SHA-224";
pub const SHA3_256: &str = "SHA-256";
pub const SHA3_384: &str = "SHA-384";
pub const SHA3_512: &str = "SHA-512";
pub const BLAKE2B: &str = "Blake2b";
pub const BLAKE2S: &str = "Blake2s";

pub const HASH_ALGORITHMS: [&str; 11] = [
    SHA1, SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, BLAKE2B,
    BLAKE2S,
];
