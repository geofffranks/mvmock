package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pborman/uuid"
)

var KEYS = map[string]*rsa.PrivateKey{}
var encoder = base64.StdEncoding.WithPadding('=')

func main() {
	router := gin.Default()
	router.GET("/v1/keys", func(c *gin.Context) {
		c.Data(200, "application/text", []byte(fmt.Sprintf("%#v", KEYS)))
		c.Done()
	})
	router.GET("/v1/cred/public_key/:uid", func(c *gin.Context) {
		key := c.Param("uid")
		if key == "" {
			c.Data(400, "application/text", []byte("No UID provided, cannot look up key.\n"))
			c.Done()
			return
		}
		k, err := findKey(key)
		if err != nil {
			c.Data(500, "application/text", []byte(err.Error()+"\n"))
			c.Done()
			return
		}
		publicKey, err := x509.MarshalPKIXPublicKey(k.Public())
		if err != nil {
			c.Data(500, "application/text", []byte(err.Error()+"\n"))
			c.Done()
			return
		}
		data := encoder.EncodeToString(publicKey)
		fmt.Printf("PubKey:\n%s\n", data)
		c.Data(200, "application/text", []byte(data))
		c.Done()
	})
	router.GET("/v1/cred/private_key/:uid", func(c *gin.Context) {
		key := c.Param("uid")
		if key == "" {
			c.Data(400, "application/text", []byte("No UID provided, cannot look up key.\n"))
			c.Done()
			return
		}
		k, err := findKey(key)
		if err != nil {
			c.Data(500, "application/text", []byte(err.Error()+"\n"))
			c.Done()
			return
		}
		privateKey := x509.MarshalPKCS1PrivateKey(k)
		data := encoder.EncodeToString(privateKey)
		fmt.Printf("PrivKey:\n%s\n", data)
		c.Data(200, "application/text", []byte(data))
		c.Done()
	})
	router.GET("/test/:scheme/:host/:port", func(c *gin.Context) {
		scheme := c.Param("scheme")
		host := c.Param("host")
		port := c.Param("port")

		expected := "This is a test. This is only a test."

		pubKey, err := getPublicKey(scheme, host, port)
		if err != nil {
			c.Data(500, "application/text", []byte(err.Error()+"\n"))
			c.Done()
			return
		}
		encrypted, err := encrypt(pubKey, expected)
		if err != nil {
			c.Data(500, "application/text", []byte(err.Error()+"\n"))
			c.Done()
			return
		}

		privKey, err := getPrivKey(scheme, host, port)
		if err != nil {
			c.Data(500, "application/text", []byte(err.Error()+"\n"))
			c.Done()
			return
		}
		decrypted, err := decrypt(privKey, encrypted)
		if err != nil {
			c.Data(500, "application/text", []byte(err.Error()+"\n"))
			c.Done()
			return
		}

		if decrypted == expected {
			c.Data(200, "application/text", []byte(fmt.Sprintf("Test successful. '%s' == '%s'\n", decrypted, expected)))
		} else {
			c.Data(501, "application/text", []byte(fmt.Sprintf("Test failed. '%s' != '%s'\n", decrypted, expected)))
		}
	})
	router.Run(":" + os.Getenv("PORT"))
}

func findKey(key string) (*rsa.PrivateKey, error) {
	k, ok := KEYS[key]
	if !ok {
		var err error
		k, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		KEYS[key] = k
	}
	return k, nil
}

func getPublicKey(scheme, host, port string) (*rsa.PublicKey, error) {
	url := fmt.Sprintf("%s://%s:%s/v1/cred/public_key/test-%s", scheme, host, port, uuid.New())
	if os.Getenv("SKIP_SSL_VALIDATION") != "" && strings.ToLower(os.Getenv("SKIP_SSL_VALIDATION")) != "false" && strings.ToLower(os.Getenv("SKIP_SSL_VALIDATION")) != "no" {
		client := http.DefaultClient
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("%s returned %d: %s", host, res.StatusCode, res.Status)
	}
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	decoded := make([]byte, encoder.DecodedLen(len(data)))
	_, err = encoder.Decode(decoded, data)
	if err != nil {
		return nil, err
	}

	pubkey, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		return nil, err
	}
	var pk *rsa.PublicKey
	var ok bool
	if pk, ok = pubkey.(*rsa.PublicKey); !ok {
		return nil, err
	}
	return pk, nil
}

func getPrivKey(scheme, host, port string) (*rsa.PrivateKey, error) {
	url := fmt.Sprintf("%s://%s:%s/v1/cred/private_key/test-%s", scheme, host, port, uuid.New())
	if os.Getenv("SKIP_SSL_VALIDATION") != "" && strings.ToLower(os.Getenv("SKIP_SSL_VALIDATION")) != "false" && strings.ToLower(os.Getenv("SKIP_SSL_VALIDATION")) != "no" {
		client := http.DefaultClient
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("%s returned %d: %s", host, res.StatusCode, res.Status)
	}
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	decoded := make([]byte, encoder.DecodedLen(len(data)))
	_, err = encoder.Decode(decoded, data)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(decoded)
}

func encrypt(pubKey *rsa.PublicKey, src string) (string, error) {
	return "not encrypted", nil
}

func decrypt(privKey *rsa.PrivateKey, src string) (string, error) {
	return "not decrypted", nil
}
