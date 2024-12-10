package main

import (
	"image/png"
	"os"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"

	"github.com/oarkflow/otp"
	"github.com/oarkflow/otp/totp"
)

type User struct {
	Email string
}

func main() {
	issuer := "Orgware Construct Pvt. Ltd."
	user := User{Email: "user@example.com"}
	key, err := totp.GenerateWithOpts(
		totp.WithIssuer(issuer),
		totp.WithAccountName(user.Email),
		totp.WithGenDigits(otp.DigitsSix),
		totp.WithGenPeriod(60),
	)
	if err != nil {
		panic(err)
	}
	qrCode, _ := qr.Encode(key.URL(), qr.M, qr.Auto)
	qrCode, _ = barcode.Scale(qrCode, 200, 200)
	file, _ := os.Create("qrcode.png")
	defer file.Close()
	png.Encode(file, qrCode)
}
