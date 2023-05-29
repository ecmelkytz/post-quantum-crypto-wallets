mod wallet;

fn main() {
  let pq_btc_wallet = wallet::PqBtcWallet::new();
  println!("{:?}", &pq_btc_wallet);
}
