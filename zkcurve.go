package zkledger

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/mit-dci/zksigma"
	"github.com/mit-dci/zksigma/btcec"
)

// ZKLedgerCurve is a global cache for the curve and two generator points used in the various proof
// generation and verification functions.
var ZKLedgerCurve zksigma.ZKPCurveParams

func generateH2tothe() []zksigma.ECPoint {
	Hslice := make([]zksigma.ECPoint, 64)
	for i := range Hslice {
		m := big.NewInt(1 << uint(i))
		Hslice[i].X, Hslice[i].Y = ZKLedgerCurve.C.ScalarBaseMult(m.Bytes())
	}
	return Hslice
}

func init() {
	s256 := sha256.New()

	// This was changed in ZKSigma, but keys already generated part of the repo
	// should still work. So reverted this to what was originally in ZKLedger,

	// see:
	// hashedString := s256.Sum([]byte("This is the new random point in zksigma"))
	// HX, HY := btcec.S256().ScalarMult(btcec.S256().Gx, btcec.S256().Gy, hashedString)
	curValue := btcec.S256().Gx
	s256.Write(new(big.Int).Add(curValue, big.NewInt(2)).Bytes()) // hash G_x + 2 which

	potentialXValue := make([]byte, 33)
	binary.LittleEndian.PutUint32(potentialXValue, 2)
	for i, elem := range s256.Sum(nil) {
		potentialXValue[i+1] = elem
	}

	H, err := btcec.ParsePubKey(potentialXValue, btcec.S256())
	if err != nil {
		panic(err)
	}
	ZKLedgerCurve = zksigma.ZKPCurveParams{
		C: btcec.S256(),
		G: zksigma.ECPoint{btcec.S256().Gx, btcec.S256().Gy},
		H: zksigma.ECPoint{H.X, H.Y},
	}
	ZKLedgerCurve.HPoints = generateH2tothe()
}
