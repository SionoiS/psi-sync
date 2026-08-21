//! XOR fingerprint of item hashes (LIP-182).

/// XOR `hash` into `acc`.
pub fn xor_into(acc: &mut [u8; 32], hash: &[u8; 32]) {
    for (a, h) in acc.iter_mut().zip(hash.iter()) {
        *a ^= *h;
    }
}

/// XOR a sequence of 32-byte hashes. Empty input yields `[0; 32]`.
#[cfg(test)]
pub fn xor_slice<'a, I>(hashes: I) -> [u8; 32]
where
    I: IntoIterator<Item = &'a [u8; 32]>,
{
    let mut acc = [0u8; 32];
    for hash in hashes {
        xor_into(&mut acc, hash);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_identity() {
        let a = [0x11u8; 32];
        assert_eq!(xor_slice([&a, &a]), [0u8; 32]);
        assert_eq!(xor_slice([&a]), a);
        assert_eq!(xor_slice([]), [0u8; 32]);
    }

    #[test]
    fn xor_associative() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let c = [0x04u8; 32];
        assert_eq!(xor_slice([&a, &b, &c]), xor_slice([&c, &a, &b]));
    }
}
