package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func saveKey(filename string, size int) error {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, []byte(hex.EncodeToString(key)), 0600)
}

func main() {
	if err := saveKey("aes.key", 32); err != nil {
		fmt.Println("Error generando AES key:", err)
		return
	}
	if err := saveKey("hmac.key", 64); err != nil {
		fmt.Println("Error generando HMAC key:", err)
		return
	}
	fmt.Println("Claves generadas y guardadas")
}
