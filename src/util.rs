pub mod hash_helper {
  use ::{ sha3::{ Digest, Keccak256 }, std::convert::TryFrom };

  pub const HASH_BYTES: usize = 32;
  /// Maximum string length of a base58 encoded hash

  pub struct Hash(pub [u8; HASH_BYTES]);

  #[derive(Clone, Default)]
  pub struct Hasher {
    hasher: Keccak256,
  }

  impl Hasher {
    pub fn hash(&mut self, val: &[u8]) {
      self.hasher.update(val);
    }
    pub fn hashv(&mut self, vals: &[&[u8]]) {
      for val in vals {
        self.hash(val);
      }
    }
    pub fn result(self) -> Hash {
      // At the time of this writing, the sha3 library is stuck on an old version
      // of generic_array (0.9.0). Decouple ourselves with a clone to our version.
      Hash(<[u8; HASH_BYTES]>::try_from(self.hasher.finalize().as_slice()).unwrap())
    }
  }

  impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
      &self.0[..]
    }
  }

  pub enum ParseHashError {
  }

  impl Hash {
    pub fn new(hash_slice: &[u8]) -> Self {
      Hash(<[u8; HASH_BYTES]>::try_from(hash_slice).unwrap())
    }

    pub const fn new_from_array(hash_array: [u8; HASH_BYTES]) -> Self {
      Self(hash_array)
    }

    pub fn to_bytes(self) -> [u8; HASH_BYTES] {
      self.0
    }
  }

  /// Return a Keccak256 hash for the given data.
  pub fn hashv(vals: &[&[u8]]) -> Hash {
    {
      let mut hasher = Hasher::default();
      hasher.hashv(vals);
      hasher.result()
    }
  }

  /// Return a Keccak256 hash for the given data.
  pub fn hash(val: &[u8]) -> Hash {
    hashv(&[val])
  }

  /// Return the hash of the given hash extended with the given value.
  pub fn extend_and_hash(id: &Hash, val: &[u8]) -> Hash {
    let mut hash_data = id.as_ref().to_vec();
    hash_data.extend_from_slice(val);
    hash(&hash_data)
  }
}