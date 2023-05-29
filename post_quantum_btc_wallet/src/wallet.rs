use pqcrypto_dilithium::dilithium2::*;
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use crypto::{digest::Digest, sha2::Sha256, ripemd160::Ripemd160};

#[derive(Debug)]
pub struct PqBtcWallet {
  pub secret_key: String,
  pub public_key: String,
  pub address: String
}

impl PqBtcWallet {
  pub fn new() -> Self {
    let (public_key, secret_key) = keypair();
    let address = btc_wallet_address(&public_key);
    let sk = secret_key.as_bytes();
    let pk = public_key.as_bytes();
    PqBtcWallet {
      secret_key: hex::encode(&sk[&sk.len() - 32..]),
      public_key: hex::encode(&pk[&pk.len() - 32..]),
      address: address,
    }
  }
}

pub fn btc_wallet_address(public_key: &dyn PublicKey) -> String {
  let public_key = public_key.as_bytes();
  let address = base58check(&public_key);
  bs58::encode(address).into_string()
}

pub fn ripemd160(input: &[u8]) -> Vec<u8> {
  let mut ripemder = Ripemd160::new();
  let mut hash = vec![0; ripemder.output_bytes()];
  ripemder.input(&input); 
  ripemder.result(&mut hash);
  hash
}

pub fn sha256(input: &[u8]) -> Vec<u8> {
  let mut hasher = Sha256::new();
  let mut hash = vec![0; hasher.output_bytes()];
  hasher.input(&input); 
  hasher.result(&mut hash);
  hash
}

pub fn hash160(input: &[u8]) -> Vec<u8> {
  let mut res = sha256(&input);
  res = ripemd160(&res);
  res
}

fn double_sha256(bytes : &Vec<u8>) -> Vec<u8> {
  let mut hasher = Sha256::new();
  let mut hash = vec![0; hasher.output_bytes()];
  hasher.input(&bytes);
  hasher.result(&mut hash);
  hasher.reset();
  hasher.input(&hash);
  hasher.result(&mut hash);
  hash
}

pub fn base58check(public_key: &[u8]) -> Vec<u8> {
  let mut address = Vec::new();
  address.extend(vec![0x00]);
  let hash_pk = hash160(&public_key);
  address.extend(hash_pk);
  let double_sha = double_sha256(&address);
  let checksum = hex::encode(&double_sha);
  address.extend(checksum[0..4].bytes());
  address
}
