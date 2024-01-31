# P256

## Testing & Benchmarking

### Unit testing (hardhat):
```
npx hardhat test test/P256.test.js
```

### Fuzzing test (foundry):
```
forge test --match-path test/P256.t.sol
```
(takes ~40sec)

### Benchmarking (foundry):
```
FOUNDRY_OPTIMIZER_RUNS=10000 forge test --match-path test/metrics.t.sol --gas-report
```
(note that the number of optimize runs greatly affect the result of some implementations)
