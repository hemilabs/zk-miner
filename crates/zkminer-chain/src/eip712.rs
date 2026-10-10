//! EIP-712 signing for atomic fast-path operations.

use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use anyhow::{Context, Result};

/// EIP-712 domain separator for HemiProve.
/// name = "HemiProve", version = "1"
pub struct HemiProveDomain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: Address,
}

impl HemiProveDomain {
    pub fn new(chain_id: u64, verifying_contract: Address) -> Self {
        Self {
            name: "HemiProve".to_string(),
            version: "1".to_string(),
            chain_id,
            verifying_contract,
        }
    }

    /// Compute the EIP-712 domain separator hash.
    pub fn separator(&self) -> B256 {
        let type_hash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let name_hash = keccak256(self.name.as_bytes());
        let version_hash = keccak256(self.version.as_bytes());

        let mut encoded = Vec::with_capacity(160);
        encoded.extend_from_slice(type_hash.as_slice());
        encoded.extend_from_slice(name_hash.as_slice());
        encoded.extend_from_slice(version_hash.as_slice());
        encoded.extend_from_slice(&U256::from(self.chain_id).to_be_bytes::<32>());
        encoded.extend_from_slice(&{
            let mut buf = [0u8; 32];
            buf[12..].copy_from_slice(self.verifying_contract.as_slice());
            buf
        });

        keccak256(&encoded)
    }
}

/// FULFILL_TYPEHASH = keccak256("FulfillJob(bytes32 jobId,bytes32 publicValuesHash,address submitter,uint256 deadline)")
pub fn fulfill_typehash() -> B256 {
    keccak256(
        "FulfillJob(bytes32 jobId,bytes32 publicValuesHash,address submitter,uint256 deadline)",
    )
}

/// Sign a FulfillJob EIP-712 message for claimAndFulfillJob.
pub async fn sign_fulfill_job(
    signer: &PrivateKeySigner,
    domain: &HemiProveDomain,
    job_id: B256,
    public_values_hash: B256,
    submitter: Address,
    deadline: U256,
) -> Result<Bytes> {
    let struct_hash = {
        let mut encoded = Vec::with_capacity(160);
        encoded.extend_from_slice(fulfill_typehash().as_slice());
        encoded.extend_from_slice(job_id.as_slice());
        encoded.extend_from_slice(public_values_hash.as_slice());
        encoded.extend_from_slice(&{
            let mut buf = [0u8; 32];
            buf[12..].copy_from_slice(submitter.as_slice());
            buf
        });
        encoded.extend_from_slice(&deadline.to_be_bytes::<32>());
        keccak256(&encoded)
    };

    let domain_separator = domain.separator();

    // EIP-712: "\x19\x01" || domainSeparator || structHash
    let mut message = Vec::with_capacity(66);
    message.extend_from_slice(b"\x19\x01");
    message.extend_from_slice(domain_separator.as_slice());
    message.extend_from_slice(struct_hash.as_slice());

    let digest = keccak256(&message);
    let signature = signer
        .sign_hash(&digest)
        .await
        .context("Failed to sign EIP-712 message")?;

    Ok(Bytes::from(signature.as_bytes().to_vec()))
}
