use sha2::{ Digest, Sha256 };
use sha3::Keccak256;

const LEVEL_ARRAY: [&str; 13] = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"];
const SIZE_ARRAY: [usize; 13] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

#[derive(Clone, Debug)]
pub struct MerkleNode {
  pub row: String,
  pub index: usize,
  pub hash: Vec<u8>,
}

pub struct MerkleTree {
  height: usize,
  nodes: Vec<Vec<MerkleNode>>,
  root: MerkleNode,
}

impl MerkleTree {
  fn new(mut hashes: Vec<Vec<u8>>, hash_fn: fn(&[u8]) -> Vec<u8>) -> Self {
    let mut height = 0;
    for (i, &size) in SIZE_ARRAY.iter().enumerate() {
      if size >= hashes.len() {
        height = i + 1;
        break;
      }
    }

    while hashes.len() < SIZE_ARRAY[height - 1] {
      hashes.push(vec![0; 32]); // Fill with zeroes to match the expected size
    }

    let leaf_nodes = hashes
      .into_iter()
      .enumerate()
      .map(|(i, hash)| MerkleNode {
        row: LEVEL_ARRAY[0].to_string(),
        index: i,
        hash,
      })
      .collect::<Vec<MerkleNode>>();

    let mut nodes = vec![leaf_nodes];
    for level in 1..height {
      let sub_nodes = &nodes[level - 1];
      let mut new_nodes = Vec::new();

      for chunk in sub_nodes.chunks(2) {
        let hash = match chunk.len() {
          2 => {
            let (first, second) = (&chunk[0].hash, &chunk[1].hash);
            let combined = if first <= second {
              [first.as_slice(), second.as_slice()].concat()
            } else {
              [second.as_slice(), first.as_slice()].concat()
            };
            hash_fn(&combined)
          }
          _ => chunk[0].hash.clone(),
        };
        new_nodes.push(MerkleNode {
          row: LEVEL_ARRAY[level].to_string(),
          index: new_nodes.len(),
          hash,
        });
      }
      nodes.push(new_nodes);
    }

    let root = nodes.last().unwrap().first().unwrap().clone();
    MerkleTree { height, nodes, root }
  }

  pub fn height(&self) -> usize {
    self.height
  }

  pub fn nodes(&self) -> Vec<Vec<MerkleNode>> {
    self.nodes.clone()
  }

  pub fn root(&self) -> MerkleNode {
    self.root.clone()
  }

  pub fn proofs(&self, index: usize) -> Vec<[u8;32]> {
    let mut proofs = Vec::new();
    let mut current_index = index;
    for level_nodes in self.nodes.iter().take(self.height - 1) {
      let pair_index = if current_index % 2 == 0 { current_index + 1 } else { current_index - 1 };
      if pair_index < level_nodes.len() {
        proofs.push(level_nodes[pair_index].hash.clone().try_into().unwrap());
      }
      current_index /= 2;
    }
    proofs
  }
}

pub struct MerkleTreeKeccak {
  pub tree: MerkleTree,
}

impl MerkleTreeKeccak {
  pub fn new(hashes: Vec<Vec<u8>>) -> Self {
    let tree = MerkleTree::new(hashes, Self::keccak256);
    MerkleTreeKeccak { tree }
  }

  pub fn keccak256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
  }
}

pub struct MerkleTreeSha256 {
  pub tree: MerkleTree,
}

impl MerkleTreeSha256 {
  pub fn new(hashes: Vec<Vec<u8>>) -> Self {
    let tree = MerkleTree::new(hashes, Self::sha256);
    MerkleTreeSha256 { tree }
  }

  fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
  }
}