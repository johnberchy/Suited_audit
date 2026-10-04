# I TESTED EVERYTHING BELOW LOCALLY ON MY BASH TERMINAL. THE TESTS USES A MOCK TOKEN AND THROWAWAY KEYS

# REPRODUCTION STEPS / PROOF OF CONCEPT

1. Foundry Installation

```bash
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc     
foundryup
forge --version
```

If you get forge: command not found, add export PATH="$PATH:$HOME/.foundry/bin" to ~/.bashrc and source

2. Created my project
   
```bash
cd ~
forge init suited-poc
cd suited-poc
```

forge init already installs forge-std.

3. Install OpenZeppelin v5
   
```bash
forge install OpenZeppelin/openzeppelin-contracts@v5.1.0
```

5. Configure foundry.toml

Replace the contents of foundry.toml with:

```
toml
[profile.default]
src = "src"
test = "test"
libs = ["lib"]
solc_version = "0.8.24"
evm_version = "cancun"
remappings = [
  "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
  "forge-std/=lib/forge-std/src/"
]
```

6. Add the main Suited.sol contract(src/contract/Suited.sol) and the PoC contract(test/contract/SuitedPoC.sol) from my repo
   
 Paste it in with
 
```bash 
 nano src/Suited.sol
````

```bash
nano test/SuitedPoC.sol
```

8. Compile
   
```bash
forge build
```

This should finish with some warnings but the tests still passes

8. Run all PoCs
   
```bash
forge test --match-contract SuitedPoC -vv
```

9. Inspect all attacks one after the other
    
for medium 1 findings

```bash
forge test --match-test test_F1_settlerDrains -vvvv
```

```bash
forge test --match-test test_F1_victimExitHatch -vvvv
```

 ```bash
forge test --match-test test_F1_ownerKeyEscalates -vvvv
```

for medium 2 findings

 ```bash
forge test --match-test test_F2A_exitClaimedAfter -vvvv
```

 ```bash
forge test --match-test test_F2B_preSignedWithdraw -vvvv
```

 ```bash
forge test --match-test test_F2C_pauseFreezesSettlement -vvvv
```

You should see six tests marked [PASS]:
A pass means the vulnerable behavior was reproduced, because each test asserts the exploit succeeds.

