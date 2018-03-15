package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

var (
	grabIDServerScheme = "http"
	grabIDServerHost   = "localhost"
	grabIDServerPort   = "8001"
)

// LoginResult ...
type LoginResult struct {
	Jwt                   string `json:"jwt"`
	RegisteredWithService bool   `json:"registeredWithService"`
}

// LoginWithGrabViaFacebook ...
func LoginWithGrabViaFacebook(accessToken string, serviceID string) (*LoginResult, error) {

	url := ""
	if grabIDServerPort == "" {
		url = fmt.Sprintf("%s://%s/v1/me/tokens", grabIDServerScheme, grabIDServerHost)
	} else {
		url = fmt.Sprintf("%s://%s:%s/v1/me/tokens", grabIDServerScheme, grabIDServerHost, grabIDServerPort)
	}

	fmt.Printf("[loginWithGrabViaFacebook] Grab id url : %s", url)

	reqPayload := make(map[string]string)
	reqPayload["loginMethod"] = "FACEBOOK"
	reqPayload["serviceID"] = serviceID
	reqPayload["userPassword"] = accessToken

	jsonBytes, err := jsonMarshal(reqPayload, false)
	if err != nil {
		fmt.Printf("[loginWithGrabViaFacebook] Unable to serialize request into JSON. Error: %v, Request: +%v", err, reqPayload)
		return nil, err
	}
	fmt.Printf("/me/tokens payload is %s", string(jsonBytes))

	reqReader := bytes.NewBuffer(jsonBytes)
	req, err := http.NewRequest("POST", url, reqReader)
	if err != nil {
		fmt.Printf("[loginWithGrabViaFacebook] Unable to create HTTP POST request. Error: %v, Request: +%v", err, reqPayload)
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[loginWithGrabViaFacebook] Error doing POST operation. Error: %v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[loginWithGrabViaFacebook] POST operation returned non succesful code of %s. Error: %v", resp.Status, err)
		return nil, err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[loginWithGrabViaFacebook] Error reading POST operation response. Error: %v", err)
		return nil, err
	}

	result := &LoginResult{}
	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		fmt.Printf("[loginWithGrabViaFacebook] Error marshalling POST response to result. Error: %v", err)
		return nil, err
	}

	return result, nil
}

//func registerUserWithService(serviceID string, serviceApiKey string, userSafeID string, userJTI string) {
//v1/users/%s/services
//}
