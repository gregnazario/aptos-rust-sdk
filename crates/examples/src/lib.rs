#[cfg(test)]
mod tests {
    use aptos_rust_sdk::client::builder::AptosClientBuilder;
    use aptos_rust_sdk::client::config::AptosNetwork;
    use aptos_rust_sdk_types::api_types::transaction::RawTransaction;
    use aptos_rust_sdk_types::crypto::ed25519::private_key::Ed25519PrivateKey;
    use aptos_rust_sdk_types::crypto::traits::PrivateKey;
    use std::hash::Hash;

    #[tokio::test]
    async fn submit_transaction() {
        let builder = AptosClientBuilder::new(AptosNetwork::devnet());
        let client = builder.build();

        let state = client.get_state().await.unwrap();

        let bytes: [u8; 32] = [0u8; 32];
        let key = Ed25519PrivateKey::from(bytes);
        let pubkey = key.public_key();
    }
}
