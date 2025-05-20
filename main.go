package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"io"
)

var secretKey = []byte("12345678901234567890123456789012") // 32 bytes (AES-256)
var hmacKey   = []byte("clave-secreta-para-hmac")          // puede ser distinta si quieres

type Telemetria struct {
	Ritmo  int    `json:"ritmo"`
	Unidad string `json:"unidad"`
}

// Cifrado AES CBC con padding PKCS7
func encryptAES(plainText []byte, key []byte) (iv []byte, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	iv = make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	// PKCS7 Padding
	padding := aes.BlockSize - len(plainText)%aes.BlockSize
	padtext := bytesRepeat(byte(padding), padding)
	plainText = append(plainText, padtext...)

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext = make([]byte, len(plainText))
	mode.CryptBlocks(ciphertext, plainText)

	return
}

// HMAC-SHA256 sobre los datos cifrados
func generateHMAC(data []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// reemplazo simple de bytes.Repeat sin importar importación extra
func bytesRepeat(b byte, count int) []byte {
	res := make([]byte, count)
	for i := range res {
		res[i] = b
	}
	return res
}

func main() {
	r := gin.Default()

	r.GET("/telemetria", func(c *gin.Context) {
		// 1. Crear datos
		datos := Telemetria{Ritmo: 78, Unidad: "bpm"}
		jsonData, err := json.Marshal(datos)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "marshal"})
			return
		}

		// 2. Cifrar
		iv, encryptedData, err := encryptAES(jsonData, secretKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "encrypt"})
			return
		}

		// 3. Juntar IV + cifrado para enviar
		payload := append(iv, encryptedData...)
		payloadBase64 := base64.StdEncoding.EncodeToString(payload)

		// 4. Generar HMAC de los datos cifrados
		firma := generateHMAC(payload, hmacKey)

		// 5. Enviar
		c.JSON(http.StatusOK, gin.H{
			"data":  payloadBase64,
			"firma": firma,
		})
	})

	r.RunTLS(":443", "cert.pem", "key.pem")
}
