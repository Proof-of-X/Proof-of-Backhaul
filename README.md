# Proof-of-Backhaul

Proof of Backhaul is a decentralised speed-test which can be used by a “payer”

to determine the backhaul capacity of a “prover” with the help of a pool of

“challengers“ who send the challenge traffic to the prover.

Please read:

[GitBook link](https://witness-chain.gitbook.io/witness-chain/proof-of-backhaul/introduction)

## Running a challenger

We currently support Linux/Mac/Windows-WSL.

Edit the `config/pob/challenger.json` file
to change the `walletPublicKey` and `bandwidth`.

The `walletPublicKey` is where rewards go; and the `bandwidth` is the amount of bandwidth you wish to allocate
for PoB challenges.

### To check if everything is working fine

```
./run-pob-challenger
```

### To run in production 

```
./run-pob-challenger-in-tmux
```

## For developers

### Building the PoB binaries
```
dart/run/build-pob
```

### Running the challenger code

```
dart/bin/pob/run-pob-challenger
```

To run in background

```
dart/bin/pob/run-pob-challenger-in-tmux
```
