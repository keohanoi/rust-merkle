# Rust Merkle

This is a Rust implementation of a Merkle tree.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

What things you need to install the software and how to install them:

- Rust: You can install it from [here](https://www.rust-lang.org/tools/install)

### Installing

A step by step series of examples that tell you how to get a development environment running:

```bash
git clone git@github.com:nguyentruongkhang22/rust-merkle.git
cd rust-merkle
cargo build
```

Running the tests
Explain how to run the automated tests for this system:

```bash
cargo test
```

### Example
## Finding the root of a Merkle tree
  
```rust
use rust_merkle::merkle::{MerkleTreeKeccak, MerkleTreeSha256};

fn main() {
  // Example usage:
  let hashes = vec![vec![0; 32], vec![1; 32], vec![2; 32], vec![3; 32]];
  let tree_keccak = MerkleTreeKeccak::new(hashes.clone());
  let tree_sha256 = MerkleTreeSha256::new(hashes.clone());

  println!("Root (Keccak): {:?}", tree_keccak.tree.root());
  println!("Root (SHA256): {:?}", tree_sha256.tree.root());
}
```

## Built With Specific Struct
```rust
use rust_merkle::merkle::{MerkleTreeKeccak, MerkleTreeSha256};

pub struct TestStruct {
  pub field1: String,
  pub field2: u64,
}

let vals: Vec<TestStruct> = vec![
  TestStruct {
    field1: "test1".to_string(),
    field2: 1,
  },
  TestStruct {
    field1: "test2".to_string(),
    field2: 2,
  },
  TestStruct {
    field1: "test3".to_string(),
    field2: 3,
  }
];
let mut hashes: Vec<Vec<u8>> = vec![];

for i in 0..vals.len() {
  let bytes = [vals[i].field1.as_bytes(), &vals[i].field2.to_string().as_bytes()].concat();
  let hash = MerkleTreeKeccak::keccak256(&bytes);
  hashes.push(hash);
}

let tree_keccak = MerkleTreeKeccak::new(hashes.clone());
```