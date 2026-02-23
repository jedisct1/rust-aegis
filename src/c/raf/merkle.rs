use super::Error;

pub trait MerkleHasher {
    fn hash_len(&self) -> usize;
    fn hash_leaf(&self, out: &mut [u8], chunk: &[u8], chunk_idx: u64) -> Result<(), Error>;
    fn hash_parent(
        &self,
        out: &mut [u8],
        left: &[u8],
        right: &[u8],
        level: u32,
        node_idx: u64,
    ) -> Result<(), Error>;
    fn hash_empty(&self, out: &mut [u8], level: u32, node_idx: u64) -> Result<(), Error>;
    fn hash_commitment(
        &self,
        out: &mut [u8],
        structural_root: &[u8],
        ctx: &[u8],
        file_size: u64,
    ) -> Result<(), Error>;
}
