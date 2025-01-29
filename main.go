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

type licensefile struct {
	expiry_date string
	user_id     string
}

var Encryptedfile string = "Encryptedfile.txt"

// function used to read the expiry date
func (eg *licensefile) read_info(date *string, user_id *string) {
	fmt.Println("Enter the expiry date of the license file in YYYY-MM-DD format:")
	fmt.Scanln(&eg.expiry_date)
	*date = eg.expiry_date
	fmt.Println("Enter the User Id:")
	fmt.Scanln(&eg.user_id)
	*user_id = eg.user_id
}

// function to read and write file data
func (eg *licensefile) open_file() {
	//opening and writing license file
	// noabbrevation in function name
	fmt.Println("Enter the filename with type:")
	fmt.Scanln(&filename)
	file, err := os.OpenFile(filename, os.O_WRONLY, 0644)

	if err != nil {
		fmt.Println("Error in opening the file")
	}

	file.WriteString("Expiry_date:")
	file.WriteString(eg.expiry_date)
	file.WriteString("\n")
	file.WriteString("User_id:")
	file.WriteString(eg.user_id)
}

// function to decrypt the encrypted file
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

// funtion to encrypt the raw file
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

	Sprivatekey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println("error in generating private key")

	}

	encryptfile(filename, "Encryptedfile.txt", Sprivatekey)

}

func main() {
	lcfile := licensefile{}
	var temp1, temp2 string
	lcfile.read_info(&temp1, &temp2)
	fmt.Printf("The expiry date of the license file is %s \n", temp1)
	lcfile.open_file()
	GeneratePrivatekeyFile()
}
