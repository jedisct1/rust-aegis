use super::Error;

/// Hash functions used to build and verify the optional Merkle tree over a RAF file.
///
/// A file can be associated with a Merkle tree so that the integrity of the
/// whole file can be checked against a single commitment. Implement this trait
/// to plug in a hash function of your choice. Each method writes exactly
/// [`hash_len`](MerkleHasher::hash_len) bytes into `out`. Domain-separation
/// parameters (`level`, `node_idx`, `chunk_idx`) are provided so that leaves,
/// internal nodes, and empty subtrees hash distinctly.
pub trait MerkleHasher {
    /// Returns the length in bytes of every hash this hasher produces.
    fn hash_len(&self) -> usize;
    /// Hashes the plaintext of chunk `chunk_idx` into a leaf node.
    fn hash_leaf(&self, out: &mut [u8], chunk: &[u8], chunk_idx: u64) -> Result<(), Error>;
    /// Hashes two child hashes into their parent node at the given tree `level` and `node_idx`.
    fn hash_parent(
        &self,
        out: &mut [u8],
        left: &[u8],
        right: &[u8],
        level: u32,
        node_idx: u64,
    ) -> Result<(), Error>;
    /// Produces the hash of an empty subtree at the given `level` and `node_idx`.
    fn hash_empty(&self, out: &mut [u8], level: u32, node_idx: u64) -> Result<(), Error>;
    /// Binds the structural root, a context string, and the file size into the final commitment.
    fn hash_commitment(
        &self,
        out: &mut [u8],
        structural_root: &[u8],
        ctx: &[u8],
        file_size: u64,
    ) -> Result<(), Error>;
}
