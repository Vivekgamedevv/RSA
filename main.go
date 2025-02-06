package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
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

	file.WriteString("expiry_date:")
	file.WriteString(eg.expiry_date)
	file.WriteString("\n")
	file.WriteString("User_id:")
	file.WriteString(eg.user_id)
}

// funtion to encrypt the raw file
func encryptfile(inputfile string, outputfile string, Sprivatekey *rsa.PrivateKey) error {

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

	//decryptfile(Encryptedfile, "decryptedfile.txt", Sprivatekey)

	return nil

}

// function to decrypt the encrypted file
func decryptfile(encryptedfile, outputfile string, Sprivatekey *rsa.PrivateKey) error {
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

	return nil
}

// Function used to generate system private and public key
func GeneratePrivatekeyFile() *rsa.PrivateKey {

	Sprivatekey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println("error in generating private key")

	}

	c := Sprivatekey
	privKeyBytes := x509.MarshalPKCS1PrivateKey(Sprivatekey)

	// Create a PEM block
	privPemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	// Create or overwrite the file
	file, err := os.Create("privatekey.pem")
	if err != nil {
		fmt.Println("Failed to create a privatekey file")
	}
	defer file.Close()

	// Encode the PEM block to the file
	err = pem.Encode(file, privPemBlock)
	if err != nil {
		fmt.Println("Failed to encode the pem block to the file")
	}

	//encryptfile(filename, "Encryptedfile.txt", Sprivatekey)
	return c
}

// // validation of license AK
// func validateLicense(filePath string) (bool, error) {
// 	file, err := os.Open(filePath)
// 	if err != nil {
// 		return false, fmt.Errorf("error opening the file: %w", err)
// 	}
// 	defer file.Close()

// 	content, err := io.ReadAll(file)
// 	if err != nil {
// 		return false, fmt.Errorf("error reading the file: %w", err)
// 	}

// 	lines := strings.Split(string(content), "\n")
// 	for _, line := range lines {
// 		if strings.HasPrefix(line, "expiry_date:") {
// 			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "expiry_date:"))
// 			expiryDate, err := time.Parse("2006-01-02", dateStr)
// 			if err != nil {
// 				return false, fmt.Errorf("invalid date format in the file: %w", err)
// 			}

// 			if time.Now().Before(expiryDate) {
// 				return true, nil
// 			}
// 			return false, nil
// 		}
// 	}
// 	return false, fmt.Errorf("expiry_date not found in the file")
// }

// checing if the License file exists or no

// func checkFileExists(filePath string) bool {
// 	_, err := os.Stat(filePath)
// 	if os.IsNotExist(err) {
// 		return false
// 	}
// 	return err == nil
// }

// If the validation is true now the contents in the file will be shown

// func displaycontentinfile(filepath string) error {

// 	file, err := os.Open(filepath)
// 	if err != nil {
// 		return fmt.Errorf("error while opening the file !! : %w", err)
// 	}
// 	defer file.Close()

// 	content, err := io.ReadAll(file)
// 	if err != nil {
// 		return fmt.Errorf("error while reading the file !! : %w ", err)

// 	}

// 	fmt.Println("Input given by user :")

// 	fmt.Println(string(content))
// 	return nil

// }

func main() {
	lcfile := licensefile{}
	var temp1, temp2 string
	lcfile.read_info(&temp1, &temp2)
	fmt.Printf("The expiry date of the license file is %s \n", temp1)
	lcfile.open_file()
	prkey := GeneratePrivatekeyFile()
	encryptfile(filename, "Encryptedfile.txt", prkey)

	err := encryptfile(filename, "Encryptedfile.txt", prkey)

	if err != nil {
		fmt.Println("Error in encrypting the file")
	}

	fmt.Println("File encrypted succesfully")

	fmt.Println(prkey)

	var condi string
	fmt.Println("Do you want to decrypt the file(Y/N):")
	fmt.Scanln(&condi)
	if condi == "Y" {

		inputkey := new(rsa.PrivateKey)
		fmt.Println("Input the private key to decrypt:")

		err = decryptfile(Encryptedfile, "decryptedfile.txt", inputkey)
		if err != nil {
			fmt.Println("Error in decrypting the file")
		}

		fmt.Println("File decrypted succesfully")

	} else if condi == "N" {
		fmt.Println("File decryption stopped")
	} else {
		fmt.Println("Wrong input")
	}

	// // validation of license
	// valid, err := validateLicense(filename)
	// if err != nil {
	// 	fmt.Println("Error validating the license:", err)
	// 	return
	// }

	// // to display the contents present inside the file

	// if valid {
	// 	fmt.Println("------------------------------------------")
	// 	fmt.Println(" License is valid. Access granted.\n", "displaying the contents inside the file:")
	// 	fmt.Println("-----------------------------------------")
	// 	err := displaycontentinfile(filename)
	// 	if err != nil {
	// 		fmt.Println("error while displaying the file : %w", err)
	// 	}
	// } else {
	// 	fmt.Println("License has expired. Access denied !!! .")
	// }

	// // file checking for every 24 hours
	// if checkFileExists(filename) {
	// 	fmt.Println("File exists.")
	// } else {

	// 	fmt.Println("File does not exist.")
	// }

	// time.Sleep(10 * time.Second)

}
