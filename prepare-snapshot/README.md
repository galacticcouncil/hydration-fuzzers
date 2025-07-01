
## How to prepare a snapshot for the fuzzer

### Take a snapshot of mainnet state for selected pallets

It would be best to specify exact block hash and remember the block number as well.

```
./target/release/scraper save-storage --pallet Omnipool Stableswap AssetRegistry EVM DynamicFees EmaOracle MultiTransactionPayment Tokens Balances System --uri wss://rpc.hydradx.cloud:443
```

### Copy the mainnet state to the `data` directory

```bash
cp <path-to-snapsho> data/MAINNET
```

### Prepare the snapshot

```bash
cargo build
./target/debug/prepare-snapshot
```

### Move the generated snapshot to the `data` directory of the fuzzer

```bash
mv data/MOCK_SNAPSHOT ../runtime-fuzzer/data/
```