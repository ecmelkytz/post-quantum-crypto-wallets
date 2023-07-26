use anyhow::Result;
use std::{fs::File, str::FromStr, io::BufReader};
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use pqcrypto_dilithium::dilithium2::*;
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait};
use web3::{
  signing::keccak256,
  transports::ws::WebSocket,
  types::{Address, U256},
  Web3
};

pub struct PqEthWallet {
  pub public_key: PublicKey,
  pub secret_key: SecretKey,
  pub address: String,
}

#[derive(Serialize, Deserialize)]
pub struct CustomerWallet {
  pub public_key: String,
  pub secret_key: String,
  pub address: String,
}

impl PqEthWallet {
  pub fn new() -> Self {
    let (public_key, secret_key) = keypair();
    let address: Address = eth_wallet_address(&public_key);
    PqEthWallet {
      public_key: public_key,
      secret_key: secret_key,
      address: format!("{:?}", address)
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

  pub fn infos(&self) -> Value  {
    let params = json!({"public_key": &self.get_public_key(),
                        "secret_key":&self.get_secret_key(), 
                        "address": &self.address});
    params
  } 

  pub fn save_to_file(&self, file_path: &str) -> Result<()> {
    let infos = self.infos();
    std::fs::write(
      file_path,
      serde_json::to_string(&infos).unwrap()
    )?;
    Ok(())
  }
  
  pub fn read_from_file(file_path: &str) -> Result<CustomerWallet> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let wallet: CustomerWallet = serde_json::from_reader(reader)?;
    Ok(wallet)
  }
}

impl CustomerWallet {
  pub async fn get_balance(&self, web3: &Web3<WebSocket>) -> Result<f64> {
    let wallet_address = Address::from_str(&self.address)?;
    let balance = web3.eth().balance(wallet_address, None).await?;
    Ok(wei_to_eth(balance))
  }
}

pub fn eth_wallet_address(public_key: &PublicKey) -> Address {
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
