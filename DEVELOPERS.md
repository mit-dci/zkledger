# zkLedger File Structure

### Top Level

All the zkLedger source code is contained in the top level directory. This includes auditor, bank, and ledger functionality.

- **audit.go**
- **bank.go**
- **clients.go**
- **debug.go**
- **ledger.go**
- **pki.go**
- **system_test.go**
- **testutil.go**
- **transaction.go**

### cmd/

This directory contains the control infrastructure to actually run a zkLedger instance.

- **apl-auditor/**
- **apl-bank/**
- **apl-ledger/**
- **keygen/**
- **setup/**

To run experiments, `setup/` contains a testing harness for local and remote tests.

- `main.go`: contains preset tests (e.g. r50TX_herf where every bank
  you pass in performs 50 transactions and at the end the Herfindahl
  index is calculated between them) but also has the flexibility to
  insert others. It also can execute tests when servers are on
  different machines.
- `apl_env.go`: contains methods to create the environment for zkLedger to execute, either locally or remotely. 
- `keys/`: **DO NOT USE THESE IN PRODUCTION ENVIRONMENTS** contains a collection of 50 bank public/private key pairs for testing. 