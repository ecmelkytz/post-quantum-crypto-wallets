mod wallet;

fn main() {
  let pq_btc_wallet = wallet::PqBtcWallet::new();
  println!("PqBtcWallet => {}", pq_btc_wallet.infos());
}
