package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"

	cfenv "github.com/cloudfoundry-community/go-cfenv"
	"github.com/gin-gonic/gin"
	"github.com/pborman/uuid"
)

var KEYS = map[string]*rsa.PrivateKey{}

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
		block := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKey,
		}
		data := pem.EncodeToMemory(block)

		cmd := exec.Command(findOpenSSL(), "rsa", "-pubin", "-RSAPublicKey_out")
		cmd.Stdin = bytes.NewBuffer(data)
		out, err := cmd.Output()
		if err != nil {
			out = append(out, []byte("\n\n----\n\n"+err.Error()+"\n")...)
			c.Data(500, "application/text", out)
			c.Done()
			return
		}

		c.Data(200, "application/text", out)
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
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKey,
		}
		c.Data(200, "application/text", pem.EncodeToMemory(block))
		c.Done()
	})
	router.GET("/test/:scheme/:host/:port", func(c *gin.Context) {
		scheme := c.Param("scheme")
		host := c.Param("host")
		port := c.Param("port")
		executeTest(scheme, host, port, c)
	})

	router.Run(":" + os.Getenv("PORT"))
}

func executeTest(scheme, host, port string, c *gin.Context) {
	expected := "This is a test. This is only a test."
	label := []byte("test-mvmock-encryption")
	spaceId := getSpaceId()

	pubKey, err := getPublicKey(scheme, host, port, spaceId)
	if err != nil {
		c.Data(500, "application/text", []byte(err.Error()+"\n"))
		c.Done()
		return
	}
	encrypted, err := encrypt(pubKey, expected, label)
	if err != nil {
		c.Data(500, "application/text", []byte(err.Error()+"\n"))
		c.Done()
		return
	}

	if os.Getenv("CF_INSTANCE_IP") != "" {
		host = os.Getenv("CF_INSTANCE_IP")
		port = "1199"
		scheme = "http"
	}
	privKey, err := getPrivKey(scheme, host, port, spaceId)
	if err != nil {
		c.Data(500, "application/text", []byte("privkey error: "+err.Error()+"\n"))
		c.Done()
		return
	}
	decrypted, err := decrypt(privKey, encrypted, label)
	if err != nil {
		c.Data(500, "application/text", []byte("decryption error: "+err.Error()+"\n"))
		c.Done()
		return
	}

	if decrypted == expected {
		c.Data(200, "application/text", []byte(fmt.Sprintf("Test successful. '%s' == '%s'\n", decrypted, expected)))
	} else {
		c.Data(501, "application/text", []byte(fmt.Sprintf("Test failed. '%s' != '%s'\n", decrypted, expected)))
	}
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

func getPublicKey(scheme, host, port, unique string) (*rsa.PublicKey, error) {
	url := fmt.Sprintf("%s://%s:%s/v1/cred/public_key/%s", scheme, host, port, unique)
	fmt.Printf("Requesting %s\n", url)
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

	//	cmd := exec.Command(findOpenSSL(), "rsa", "-RSAPublicKey_in", "-pubout")
	//	cmd.Stdin = bytes.NewBuffer(data)
	//	newPub, err := cmd.CombinedOutput()
	//	if err != nil {
	//		return nil, fmt.Errorf("%s\n\n---\n%s\n", newPub, err)
	//	}

	decoded, rest := pem.Decode(data)
	if decoded == nil {
		return nil, fmt.Errorf("Couldn't parse PEM data: %v", rest)
	}

	if decoded.Type == "RSA PUBLIC KEY" {
		decoded.Type = "PUBLIC KEY"
		prefix, err := base64.StdEncoding.DecodeString("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A")
		if err != nil {
			return nil, err
		}
		decoded.Bytes = append(prefix, decoded.Bytes...)
	} else {
		fmt.Fprintf(os.Stderr, "Detected '%s' key type. Not converting from PKCS to PKIX\n", decoded.Type)
	}

	pubkey, err := x509.ParsePKIXPublicKey(decoded.Bytes)
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

func getPrivKey(scheme, host, port, unique string) (*rsa.PrivateKey, error) {
	url := fmt.Sprintf("%s://%s:%s/v1/cred/private_key/%s", scheme, host, port, unique)
	fmt.Printf("Requesting %s\n", url)
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

	decoded, rest := pem.Decode(data)
	if decoded == nil {
		return nil, fmt.Errorf("Couldn't parse PEM data: %v", rest)
	}
	return x509.ParsePKCS1PrivateKey(decoded.Bytes)
}

func encrypt(pubKey *rsa.PublicKey, src string, label []byte) (string, error) {
	encrypted, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, pubKey, []byte(src), label)
	if err != nil {
		return "", err
	}
	return string(encrypted), nil
}

func decrypt(privKey *rsa.PrivateKey, src string, label []byte) (string, error) {
	decrypted, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, privKey, []byte(src), label)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func getSpaceId() string {
	appEnv, _ := cfenv.Current()
	if appEnv == nil || appEnv.SpaceID == "" {
		return uuid.New()
	}
	return appEnv.SpaceID
}

func findOpenSSL() string {
	openssl := "/usr/local/opt/openssl/bin/openssl"
	if _, err := os.Stat(openssl); os.IsNotExist(err) {
		openssl = "openssl"
	}
	fmt.Printf("Using '%s' for openssl binary\n", openssl)
	return openssl
}
