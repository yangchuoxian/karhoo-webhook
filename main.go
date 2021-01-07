package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const webhookSecretKey = "Jal019lafj0192QtYbNzmMAsL"

type webhookEvent struct {
	ChecksumHEX string `json:"checksum"`
	Data        string `json:"data"`
}

func main() {
	// ****************************** create a http server to receive data from Karhoo for webhooks
	http.HandleFunc("/webhook", receiveWebhookData)
	err := http.ListenAndServe(":9096", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func receiveWebhookData(w http.ResponseWriter, r *http.Request) {
	signature := ""
	for k, v := range r.Header {
		if k == "x-karhoo-request-signature" {
			writeToLog("------------------ the header: " + strings.Join(v[:], ","))
			signature = strings.Join(v[:], ",")
			break
		}
	}
	if signature == "" {
		httpResponseWithError(w, http.StatusBadRequest, "no signature in request header")
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	writeToLog("------------------- body: " + string(body))
	if err != nil {
		httpResponseWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := hashRequestBody(body, []byte(webhookSecretKey))
	if err != nil {
		httpResponseWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	if signature != hash {
		httpResponseWithError(w, http.StatusUnauthorized, "signature invalid")
		return
	}
	writeToLog("############### signature: " + signature + " and body: " + string(body))
	httpResponseWithOkStatus(w)
}

func hashRequestBody(body []byte, secretKey []byte) (string, error) {
	mac := hmac.New(sha512.New, secretKey)
	_, err := mac.Write(body)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// writeToLog writes whatever to a log file
func writeToLog(logContent string) {
	logFilePath := "karhoo-webhooks.log"

	// check if log file exists, if not, create one
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		_, err := os.Create(logFilePath)
		if err != nil {
			panic(err)
		}
	}
	// open log file
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer func() { _ = f.Close() }()

	t := time.Now()
	if _, err = f.WriteString(t.Format(time.ANSIC) + "\n" + logContent + "\n"); err != nil {
		panic(err)
	}
}

// httpResponseWithError generates error http response
func httpResponseWithError(w http.ResponseWriter, httpStatus int, errorMessage string) {
	w.WriteHeader(httpStatus)
	responseMap := make(map[string]string)
	responseMap["errorMessage"] = errorMessage
	responseInJSON, _ := json.Marshal(responseMap)
	_, _ = w.Write(responseInJSON)
}

// httpResponseWithOkStatus generates ok http response
func httpResponseWithOkStatus(w http.ResponseWriter) {
	responseMap := make(map[string]string)
	responseMap["statusText"] = "ok"
	responseInJSON, _ := json.Marshal(responseMap)
	_, _ = w.Write(responseInJSON)
}
