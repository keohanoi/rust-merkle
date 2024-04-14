use util::hash_helper;
use crate::merkle::{ MerkleTreeKeccak, MerkleTreeSha256 };
pub mod util;
pub mod merkle;

fn main() {
  // Example usage:
  let hashes = vec![vec![0; 32], vec![1; 32], vec![2; 32], vec![3; 32]];
  let tree_keccak = MerkleTreeKeccak::new(hashes.clone());
  let tree_sha256 = MerkleTreeSha256::new(hashes.clone());

  println!("Root (Keccak): {:?}", tree_keccak.tree.root());
  println!("Root (SHA256): {:?}", tree_sha256.tree.root());
}
pub struct TestStruct {
  pub field1: String,
  pub field2: u64,
}

#[test]
fn verify_proof() {
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
  let root_keccak = tree_keccak.tree.root();
  let proof_keccak = tree_keccak.tree.proofs(0); // Proof for the first element

  // Resemble the leaf hash for the first element
  let test_val = TestStruct {
    field1: "test1".to_string(),
    field2: 1,
  };
  let test_val_bytes = [test_val.field1.as_bytes(), &test_val.field2.to_string().as_bytes()].concat();
  let leaf = MerkleTreeKeccak::keccak256(&test_val_bytes);
  
  assert_eq!(_verify_proof(&proof_keccak, &root_keccak.hash.try_into().unwrap(), &leaf.try_into().unwrap()), true);
}

pub fn _verify_proof(proofs: &Vec<[u8; 32]>, root: &[u8; 32], leaf: &[u8; 32]) -> bool {
  let mut computed_hash = *leaf;
  for proof in proofs.into_iter() {
    if computed_hash < *proof {
      // Hash(current computed hash + current element of the proof)
      computed_hash = hash_helper::hashv(&[&computed_hash, proof]).to_bytes();
    } else {
      // Hash(current element of the proof + current computed hash)
      computed_hash = hash_helper::hashv(&[proof, &computed_hash]).to_bytes();
    }
  }
  // Check if the computed hash (root) is equal to the provided root
  computed_hash == *root
}
