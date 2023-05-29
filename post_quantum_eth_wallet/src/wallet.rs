use anyhow::Result;
use pqcrypto_dilithium::dilithium2::*;
use std::{fs::File, str::FromStr, io::BufReader};
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use web3::{
  signing::keccak256,
  transports::ws::WebSocket,
  types::{Address, U256},
  Web3
};

#[derive(Serialize, Deserialize, Debug)]
pub struct PqEthWallet {
  pub secret_key: String,
  pub public_key: String,
  pub address: String,
}

impl PqEthWallet {
  pub fn new() -> Self {
    let (public_key, secret_key) = keypair();
    let address: Address = eth_wallet_address(&public_key);
    let sk = secret_key.as_bytes();
    let pk = public_key.as_bytes();
    PqEthWallet {
      secret_key: hex::encode(&sk[&sk.len() - 32..]),
      public_key: hex::encode(&pk[&pk.len() - 32..]),
      address: format!("{:?}", address),
    }
  }

  pub fn save_to_file(&self, file_path: &str) -> Result<()> {
    std::fs::write(
      file_path,
      serde_json::to_string_pretty(self).unwrap()
    )?;
    Ok(())
  }

  pub fn read_from_file(file_path: &str) -> Result<PqEthWallet> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let wallet: PqEthWallet = serde_json::from_reader(reader)?;
    Ok(wallet)
  }

  pub async fn get_balance(&self, web3: &Web3<WebSocket>) -> Result<f64> {
    let wallet_address = Address::from_str(&self.address)?;
    let balance = web3.eth().balance(wallet_address, None).await?;
    Ok(wei_to_eth(balance))
  }
}

pub fn eth_wallet_address(public_key: &dyn PublicKey) -> Address {
  let pk_bytes = public_key.as_bytes();
  let hash = keccak256(&pk_bytes);
  Address::from_slice(&hash[12..])
}

pub fn wei_to_eth(wei_val: U256) -> f64 {
  let wei = wei_val.as_u128() as f64;
  wei / 1_000_000_000_000_000_000.0
}

pub async fn web3_connection(ws: &str) -> Result<Web3<WebSocket>> {
  let transport = web3::transports::ws::WebSocket::new(ws).await?;
  Ok(web3::Web3::new(transport))
}
