use merkle::MerkleTreeKeccak;
use std::convert::TryInto;
pub mod merkle;

#[test]
fn main() {
  // Example usage:
  let hashes = vec![vec![0; 32], vec![1; 32], vec![2; 32], vec![3; 32]];
  let tree_keccak = crate::merkle::MerkleTreeKeccak::new(hashes.clone());
  let tree_sha256 = crate::merkle::MerkleTreeSha256::new(hashes.clone());

  println!("Root (Keccak): {:?}", tree_keccak.tree.root());
  println!("Root (SHA256): {:?}", tree_sha256.tree.root());
}

#[test]
fn verify_proof() {
  struct TestStruct {
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
    let hash = crate::merkle::MerkleTreeKeccak::keccak256(&bytes);
    hashes.push(hash);
  }

  let tree_keccak = crate::merkle::MerkleTreeKeccak::new(hashes.clone());
  let root_keccak = tree_keccak.tree.root();
  let proof_keccak = tree_keccak.tree.proofs(0); // Proof for the first element

  // Resemble the leaf hash for the first element
  let test_val = TestStruct {
    field1: "test1".to_string(),
    field2: 1,
  };
  let test_val_bytes = [test_val.field1.as_bytes(), &test_val.field2.to_string().as_bytes()].concat();
  let leaf = crate::merkle::MerkleTreeKeccak::keccak256(&test_val_bytes);

  assert_eq!(_verify_proof(&proof_keccak, &root_keccak.hash.try_into().unwrap(), &leaf.try_into().unwrap()), true);
}

fn _verify_proof(proofs: &Vec<[u8; 32]>, root: &[u8; 32], leaf: &[u8; 32]) -> bool {
  let mut computed_hash = *leaf;
  for proof in proofs.into_iter() {
    if computed_hash < *proof {
      // Hash(current computed hash + current element of the proof)
      let arr: &[&[u8]] = &[&computed_hash, &proof[..]];
      computed_hash = MerkleTreeKeccak::keccak256_arr(arr).try_into().unwrap();
    } else {
      // Hash(current element of the proof + current computed hash)
      let arr: &[&[u8]] = &[&proof[..], &computed_hash];
      computed_hash = MerkleTreeKeccak::keccak256_arr(arr).try_into().unwrap();
    }
  }
  // Check if the computed hash (root) is equal to the provided root
  computed_hash == *root
}
