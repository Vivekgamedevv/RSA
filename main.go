package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

var filename string
var Encryptedfile string = "Encryptedfile.txt"

func decryptfile(encryptedfile, outputfile string, Sprivatekey *rsa.PrivateKey) {
	file, err := os.Open(encryptedfile)
	if err != nil {
		fmt.Println("Error in opening the encrypted file")
	}

	ciphertext, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Error in reading the encrypted file")
	}

	abc := rand.Reader
	label := []byte("")
	plaintext, _ := rsa.DecryptOAEP(sha256.New(), abc, Sprivatekey, ciphertext, label)

	decryptedfile, err := os.Create(outputfile)
	if err != nil {
		fmt.Println("Error in creating the decrypted file")
	}

	_, err = decryptedfile.Write(plaintext)

	if err != nil {
		fmt.Println("Error in writing the decrypted text to the outputfile file")
	}

}

func encryptfile(inputfile string, outputfile string, Sprivatekey *rsa.PrivateKey) {

	file, err := os.Open(inputfile)
	if err != nil {
		fmt.Println("Error in opening the file")
	}

	plaintext, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("error in reading the file")
	}

	abc := rand.Reader
	label := []byte("")

	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), abc, &Sprivatekey.PublicKey, plaintext, label)

	encryptedfile, err := os.Create(outputfile)

	if err != nil {
		fmt.Println("Error in creating the outputfile")

	}

	_, err = encryptedfile.Write(ciphertext)

	if err != nil {
		fmt.Println("Error in writing the cipher text into the outputfile")
	}

	decryptfile(Encryptedfile, "decryptedfile.txt", Sprivatekey)

}

// Function used to generate system private and public key
func GeneratePrivatekeyFile() {

	fmt.Println("input the file you want to encrypt:")
	fmt.Scanln(&filename)

	Sprivatekey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println("error in generating private key")

	}

	encryptfile(filename, "Encryptedfile.txt", Sprivatekey)

}

// Function used to generate private and public key for signing and verifiying
func GeneratePrivatekeySigning() *rsa.PrivateKey {
	Uprivatekey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println("error in generating private key")

	}
	return Uprivatekey
}

// Function used to generate user private and public key
func GeneratePrivatekeyUser() *rsa.PrivateKey {
	Uprivatekey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println("error in generating private key")

	}
	return Uprivatekey
}

func main() {
	GeneratePrivatekeyFile()
}
