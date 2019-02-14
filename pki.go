package zkledger

import (
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type PKI struct {
	PK []ECPoint
	SK []*big.Int
}

func (p *PKI) Get(i int) ECPoint {
	return p.PK[i]
}

func (p *PKI) GetSK(i int) *big.Int {
	return p.SK[i]
}

// n is the number of banks. We create n+1 keys for issuers
func (p *PKI) MakeTest(n int) {
	p.PK = make([]ECPoint, n+1)
	p.SK = make([]*big.Int, n+1)
	for i := 0; i < n+1; i++ {
		p.PK[i], p.SK[i] = EC.KeyGen()
	}
	//	p.saveKeys()
}

func (p *PKI) MakeTestWithKeys(n int) {
	var err error
	p.PK, p.SK, err = p.loadPKI(n)
	check(err)
}

// load PKI takes in the number of banks in a system. Note that the issuer key is located at location n+1
func (p *PKI) loadPKI(n int) ([]ECPoint, []*big.Int, error) {
	pk := make([]ECPoint, n+1)
	sk := make([]*big.Int, n+1)

	// get working directory
	cwd, err := filepath.Abs(filepath.Dir(os.Args[0]))
	check(err)
	// append folder directory and ensure it exists
	keyDirectory := filepath.Join(cwd, "keys")
	keyDirExists, err2 := exists(keyDirectory)
	check(err2)
	if !keyDirExists {
		return pk, sk, errors.New("** Key Directory not found: " + keyDirectory)
	}

	// iterate through files
	fileList := []string{}
	err = filepath.Walk(keyDirectory, func(path string, f os.FileInfo, err error) error {
		fileList = append(fileList, path)
		return nil
	})
	check(err)

	keysFound := 0 // should be n+1 at the end

	for _, keyfile := range fileList {
		// expected file format: bi_pk or bi_sk or is_pk or is_sk where bi is bank i and 'is' is the issuer
		_, keyfileid := filepath.Split(keyfile)
		if keyfileid == "keys" {
			continue
		}
		content2 := strings.Split(keyfileid, "_")

		if content2[1] == "pk" {
			// time to load the public key
			filecontents, fileerr := ioutil.ReadFile(keyfile) // will read two integers separated by ','
			check(fileerr)
			contentpk := strings.Split(string(filecontents), ",")
			pkX, success := new(big.Int).SetString(contentpk[0], 10)
			if !success {
				return pk, sk, errors.New("Issue parsing out X value of PK: " + contentpk[0])
			}

			pkY, success := new(big.Int).SetString(contentpk[1], 10)
			if !success {
				return pk, sk, errors.New("Issue parsing out Y value of PK: " + contentpk[1])
			}

			// set it to the correct role, either issuer or bank
			if content2[0] == "is" {
				pk[n] = ECPoint{pkX, pkY}
				keysFound += 1
			} else {
				bankid, err := strconv.Atoi(content2[0][1:]) // since it is of the format
				check(err)
				if bankid >= n { // ignore any keys that are greater than ours
					continue
				}
				pk[bankid] = ECPoint{pkX, pkY}
				keysFound += 1
			}
		} else if content2[1] == "sk" { // in real world setting there should only be 1 file
			filecontents, fileerr := ioutil.ReadFile(keyfile)
			check(fileerr)

			skval := new(big.Int).SetBytes(filecontents)

			if content2[0] == "is" {
				sk[n] = skval
			} else {
				bankid, err := strconv.Atoi(content2[0][1:]) // since it is of the format
				check(err)
				if bankid >= n { // ignore any keys that are greater than ours
					continue
				}
				sk[bankid] = skval
			}
		}
	}

	if keysFound != n+1 {
		Dprintf("Key files not found for all the banks! Dumping pk map:", pk)
	}

	return pk, sk, nil
}

func (p *PKI) saveKeys() {
	// get access to current working directory
	cwd, err := filepath.Abs(filepath.Dir(os.Args[0]))
	check(err)
	keyDirectory := filepath.Join(cwd, "keys")
	keyDirExists, err2 := exists(keyDirectory)
	check(err2)

	if !keyDirExists {
		os.Mkdir(keyDirectory, 0777)
	}

	// save the first n keys which are banks keys
	for i := 0; i < len(p.PK)-1; i++ {
		filenamePK := filepath.Join(keyDirectory, "b"+strconv.Itoa(i)+"_pk")
		filenameSK := filepath.Join(keyDirectory, "b"+strconv.Itoa(i)+"_sk")

		err = ioutil.WriteFile(filenamePK, []byte(p.PK[i].X.String()+","+p.PK[i].Y.String()), 0666)
		check(err)

		err = ioutil.WriteFile(filenameSK, p.SK[i].Bytes(), 0666)
		check(err)
	}

	filenamePK := filepath.Join(keyDirectory, "is_pk")
	filenameSK := filepath.Join(keyDirectory, "is_sk")

	err = ioutil.WriteFile(filenamePK, []byte(p.PK[len(p.PK)-1].X.String()+","+p.PK[len(p.PK)-1].Y.String()), 0666)
	check(err)

	err = ioutil.WriteFile(filenameSK, p.SK[len(p.PK)-1].Bytes(), 0666)
	check(err)

}

// exists returns whether the given file or directory exists or not
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}
