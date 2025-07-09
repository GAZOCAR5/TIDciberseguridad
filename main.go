package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func loadHexKey(path string, expectedLen int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	bytes, err := hex.DecodeString(string(raw))
	if err != nil {
		return nil, err
	}
	if len(bytes) != expectedLen {
		return nil, fmt.Errorf("la clave en %s no tiene %d bytes", path, expectedLen)
	}
	return bytes, nil
}

type Telemetria struct {
	Valor  int    `json:"value"`
	Unidad string `json:"type"`
}

func getClientFingerprint(pubKey *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(pubASN1)
	return hex.EncodeToString(hash[:]), nil
}

func encryptAES(plainText []byte, key []byte) (iv []byte, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	iv = make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

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

const trustedClientPath = "user_fingerprint.txt"

func main() {
	secretKey, err := loadHexKey("scripts/aes.key", 32)
	if err != nil {
		log.Fatal("Error cargando AES key:", err)
	}
	hmacKey, err := loadHexKey("scripts/hmac.key", 64)
	if err != nil {
		log.Fatal("Error cargando HMAC key:", err)
	}

	http.HandleFunc("/telemetria", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Metodo no permitido", http.StatusMethodNotAllowed)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Cabecera Authorization requerida", http.StatusBadRequest)
			return
		}

		//verifica si existe el fingerprint registrado
		storedFingerprint, err := os.ReadFile(trustedClientPath)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "No hay fingerprint registrado. Realice handshake primero", http.StatusUnauthorized)
			} else {
				http.Error(w, "Error al leer fingerprint registrado", http.StatusInternalServerError)
			}
			return
		}

		//comparar fingerprint
		if authHeader != string(storedFingerprint) {
			http.Error(w, "Cliente no autorizado", http.StatusUnauthorized)
			return
		}
		datos := Telemetria{Valor: 10, Unidad: "weight"}
		jsonData, err := json.Marshal(datos)
		if err != nil {
			http.Error(w, "marshal", http.StatusInternalServerError)
			return
		}

		iv, encryptedData, err := encryptAES(jsonData, secretKey)
		if err != nil {
			http.Error(w, "encrypt", http.StatusInternalServerError)
			return
		}

		payload := append(iv, encryptedData...)
		payloadBase64 := base64.StdEncoding.EncodeToString(payload)
		firma := generateHMAC(payload, hmacKey)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"data":  payloadBase64,
			"firma": firma,
		})
	})

	http.HandleFunc("/handshake", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Metodo no permitido", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			PublicKey string `json:"public_key"`
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "formato JSON invalido", http.StatusBadRequest)
			return
		}

		block, _ := pem.Decode([]byte(req.PublicKey))
		if block == nil || block.Type != "PUBLIC KEY" {
			http.Error(w, "clave publica invalida", http.StatusBadRequest)
			return
		}

		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			http.Error(w, "no se pudo parsear clave publica", http.StatusBadRequest)
			return
		}

		clientPubKey, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			http.Error(w, "clave no es de tipo RSA", http.StatusBadRequest)
			return
		}

		fingerprint, err := getClientFingerprint(clientPubKey)
		if err != nil {
			http.Error(w, "error en fingerprint", http.StatusInternalServerError)
			return
		}

		if _, err := os.Stat(trustedClientPath); err == nil {
			stored, err := os.ReadFile(trustedClientPath)
			if err != nil {
				http.Error(w, "fallo al leer cliente registrado", http.StatusInternalServerError)
				return
			}
			if fingerprint != string(stored) {
				http.Error(w, "cliente no autorizado", http.StatusUnauthorized)
				return
			}
		} else {
			err := os.WriteFile(trustedClientPath, []byte(fingerprint), 0600)
			if err != nil {
				http.Error(w, "fallo al registrar cliente", http.StatusInternalServerError)
				return
			}
		}

		aesKeyHex, err := os.ReadFile("scripts/aes.key")
		if err != nil {
			http.Error(w, "no se pudo leer aes.key", http.StatusInternalServerError)
			return
		}
		aesKey, err := hex.DecodeString(string(aesKeyHex))
		if err != nil {
			http.Error(w, "formato invalido en aes.key", http.StatusInternalServerError)
			return
		}

		encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, clientPubKey, aesKey, nil)
		if err != nil {
			http.Error(w, "fallo al cifrar clave AES", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"clave_aes": base64.StdEncoding.EncodeToString(encryptedKey),
		})
	})

	log.Println("Servidor iniciado en https://localhost:443")
	http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}
