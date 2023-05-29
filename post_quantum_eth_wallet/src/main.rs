mod wallet;
use std::env;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
  dotenv::dotenv().ok();
  // let pq_eth_wallet = wallet::PqEthWallet::new();
  // pq_eth_wallet.save_to_file("pquantum_eth_wallet.json");

  let wallet = wallet::PqEthWallet::read_from_file("pquantum_eth_wallet.json")?;
  println!("{:?}", wallet);

  let sepolia_ws = env::var("INFURA_SEPOLIA_WS")?;
  let web3_connect = wallet::web3_connection(&sepolia_ws).await?;
  let block_number = web3_connect.eth().block_number().await?;
  let balance = wallet.get_balance(&web3_connect).await?;

  println!("Block number: {}", &block_number);
  println!("Wallet balance: {} Sepolia ETH", &balance);

  Ok(())
}
