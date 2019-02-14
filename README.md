# zkLedger

zkLedger is a design for a ledger which has private transactions, but supports provably-correct queries over the ledger.

Maybe you'd like to run the tests:

```
cd $GOPATH/src/github.com/mit-dci/apl
go test
```

Or, run a local experiment with a few banks, a single-server ledger, and an auditor:


```
cd cmd/setup
./setup -t simple1
```

(You can add `-debug` to get a lot of timing information and other debug output)