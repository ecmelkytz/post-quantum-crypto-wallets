use pqcrypto_dilithium::dilithium2::*;
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait};
use crypto::{digest::Digest, sha2::Sha256, ripemd160::Ripemd160};

pub struct PqBtcWallet {
  pub public_key: PublicKey,
  pub secret_key: SecretKey,
  pub address: String
}

impl PqBtcWallet {
  pub fn new() -> Self {
    let (public_key, secret_key) = keypair();
    let address = btc_wallet_address(&public_key);
    PqBtcWallet {
      public_key: public_key,
      secret_key: secret_key,
      address: address,
    }
  }

  pub fn get_public_key(&self) -> String {
    let pk = self.public_key.as_bytes();
    hex::encode(&pk[&pk.len() - 32..])
  }

  pub fn get_secret_key(&self) -> String {
    let sk = self.secret_key.as_bytes();
    hex::encode(&sk[&sk.len() - 32..])
  }

  pub fn infos(&self) -> String {
    format!("Public Key: {}, Secret Key: {}, Address: {}",
            &self.get_public_key(),
            &self.get_secret_key(),
            &self.address)

  }
}

pub fn btc_wallet_address(public_key: &PublicKey) -> String {
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
