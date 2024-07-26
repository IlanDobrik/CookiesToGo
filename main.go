package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/windows"
)

const sqlDriver = "sqlite3"

type Cookie struct {
	hostKey        string
	name           string
	encryptedValue []byte
	expiresUTC     int64
}

func decryptCookie(masterKey []byte, cookie Cookie) []byte {
	if len(cookie.encryptedValue) < 16 {
		fmt.Printf("Cookie %s %s is shorter than 16 bytes", cookie.hostKey, cookie.name)
		return nil
	}
	iv := cookie.encryptedValue[3:15]
	payload := cookie.encryptedValue[15:]

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, iv, payload, nil)
	if err != nil {
		panic(err.Error())
	}

	return plaintext
}

func getCookies(path string) []Cookie {
	const query = "SELECT host_key, name, encrypted_value, expires_utc FROM cookies"

	db, err := sql.Open(sqlDriver, path)
	if err != nil {
		panic(fmt.Sprintf("Failed to open SQL %s: %s\n", path, err))
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(fmt.Sprintf("Ping failed with: %s\n", err))
	}

	rows, err := db.Query(query)
	if err != nil {
		panic(fmt.Sprintf("Query %s failed with error %s\n", query, err))
	}
	defer rows.Close()

	var cookies []Cookie
	for rows.Next() {
		var cookie Cookie
		if err := rows.Scan(&cookie.hostKey, &cookie.name, &cookie.encryptedValue, &cookie.expiresUTC); err != nil {
			panic(fmt.Sprintf("Failed to scan row %s\n", err))
		}
		cookies = append(cookies, cookie)
	}

	if err := rows.Err(); err != nil {
		fmt.Printf("Rows error %s\n", err)
	}

	return cookies
}

func getEncryptionKey(localStatePath string) []byte {
	localStateFile, err := os.OpenFile(localStatePath, os.O_RDONLY, 0)
	if err != nil {
		panic(fmt.Sprintf("Failed to open %s with error %s", localStatePath, err))
	}
	defer localStateFile.Close()

	fileInfo, err := localStateFile.Stat()
	if err != nil {
		panic(fmt.Sprintf("Failed to get file info with error %s", err))
	}

	fileData := make([]byte, fileInfo.Size())
	if bytesRead, err := localStateFile.Read(fileData); bytesRead != int(fileInfo.Size()) || err != nil {
		panic(fmt.Sprintf("Failed to read file with error %s", err))
	}

	var localStateJson map[string]interface{}
	err = json.Unmarshal([]byte(fileData), &localStateJson)
	if err != nil {
		panic(fmt.Sprintf("Failed to unmarshel to json with error %s", err))
	}

	osCrypt := localStateJson["os_crypt"].(map[string]interface{})
	return []byte(osCrypt["encrypted_key"].(string))
}

func getMaster(localStatePath string) []byte {
	encryptedKey := getEncryptionKey(localStatePath)

	data, err := base64.StdEncoding.DecodeString(string(encryptedKey))
	if err != nil {
		panic(fmt.Sprintf("Base64 decode of %s failed with %s", encryptedKey, err))
	}

	const keyPrefix = "DPAPI"
	var dataIn, dataOut windows.DataBlob
	dataIn.Data = &data[len(keyPrefix)]
	dataIn.Size = uint32(len(data) - len(keyPrefix))

	err = windows.CryptUnprotectData(&dataIn, nil, nil, uintptr(0), nil, 0, &dataOut)
	if err != nil {
		panic(fmt.Sprintf("Call to CryptUnprotectData failed with error %s", err))
	}
	// TODO fix this
	// defer windows.LocalFree(windows.Handle(*dataOut.Data))

	return unsafe.Slice(dataOut.Data, dataOut.Size)
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Uncaught panic:", r)
		}
	}()

	const cookiesDBPath = `./Cookies.sql`
	const localStatePath = `./Local State`

	masterKey := getMaster(localStatePath)
	cookies := getCookies(cookiesDBPath)

	for _, cookie := range cookies {
		fmt.Println("Encrypted ", cookie)
		decryptedCookie := decryptCookie(masterKey, cookie)
		fmt.Println("Decrypted ", string(decryptedCookie))
	}
}
