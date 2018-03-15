package web

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/RichardKnop/go-oauth2-server/config"
	"github.com/RichardKnop/go-oauth2-server/oauth/roles"
	"github.com/RichardKnop/go-oauth2-server/session"
)

const (
	serverListenPort             = "8080"
	facebookAuthRedirectHostName = "localhost"
	fbUserRetrievalURL           = "https://graph.facebook.com/me?fields=name,email"
	grabServiceName              = "PASSENGER"
)

type facebookUserInfo struct {
	ID          string
	Email       string
	Name        string
	AccessToken string
}

var appStateForFacebookRedirect map[string]string

func init() {
	appStateForFacebookRedirect = make(map[string]string)
}

func (s *Service) loginWithFacebook(w http.ResponseWriter, r *http.Request) {

	cfg := s.GetConfig()
	fbRegTemplate := "./web/custom/fb_login.html"
	bytes, err := ioutil.ReadFile(fbRegTemplate)

	if err != nil {
		fmt.Printf("Encountered error while reading file %s, error: %v", fbRegTemplate, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fbRegTemplateStr := string(bytes)

	stateID := makeUUID()
	loginLink := getLoginLink(cfg.Facebook.ApplicationID, stateID)
	appStateForFacebookRedirect[stateID] = r.URL.RawQuery

	fbRegisterHTMLStr := strings.Replace(fbRegTemplateStr, "{{fb_login_link}}", loginLink, 1)
	fbRegisterHTMLBytes := []byte(fbRegisterHTMLStr)

	w.Header().Set("X-Frame-Options", "deny")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	w.Write(fbRegisterHTMLBytes)
}

func (s *Service) handleFacebookAuthCallback(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("X-Frame-Options", "deny")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	cfg := s.GetConfig()
	queryMap, _ := url.ParseQuery(r.URL.RawQuery)
	fbCode := queryMap["code"][0]
	stateID := queryMap["state"][0]
	appState := appStateForFacebookRedirect[stateID]

	if appState == "" {
		fmt.Printf("State ID %s returned from FB is not in our cache, rejecting the request\n", stateID)
		w.Write([]byte(getErrorHTML("Unknown state id returned from FB")))
		return
	}

	fmt.Printf("Received request with code for state of %s. Code is '%s', State value: %s\n", stateID, fbCode, appState)

	fbUserInfo, err := getUserInfoFromFacebook(cfg.Facebook, fbCode)
	if err != nil {
		fmt.Printf("Error getting user data from code ID %s\n", stateID)
		w.Write([]byte(getErrorHTML("Error getting user data from code ID")))
		return
	}

	fmt.Printf("Facebook userinfo for code %s is +%v.\n", stateID, fbUserInfo)

	lr, err := LoginWithGrabViaFacebook(fbUserInfo.AccessToken, grabServiceName)
	if err != nil {
		fmt.Printf("Error logging into grab id, error %v\n", err)
		w.Write([]byte(getErrorHTML(err.Error())))
		return
	}

	grabIDJWT, _ := jwt.Parse(lr.Jwt, nil)
	claims, _ := grabIDJWT.Claims.(jwt.MapClaims)
	if err != nil {
		fmt.Printf("Unable to parse grab id claims, error %v\n", err)
		w.Write([]byte(getErrorHTML(err.Error())))
		return
	}

	safeID := claims["sub"].(string)

	if !lr.RegisteredWithService {
		msg := fmt.Sprintf("User %s is not registered to service %s, Grab User UUID: %s. Signup with service and comeback again.", fbUserInfo.Email, grabServiceName, safeID)
		fmt.Println(msg)
		w.Write([]byte(getErrorHTML(msg)))
		return
	}

	if s.oauthService.UserExists(safeID) {
		fmt.Printf("User with email %s exists, please login", safeID)
	} else {
		oAuthUsr, err := s.oauthService.CreateUser(
			roles.User, // role ID
			safeID,     // username
			safeID,     // password
		)

		if err != nil {
			fmt.Printf("Error creating user with %s failed with error %s\n", safeID, err)
			w.Write([]byte(getErrorHTML("Unknown state id returned from FB")))
			return
		}

		fmt.Printf("Creating user succeeded. User: +%v\n", oAuthUsr)
	}

	// Login succeeded, user exists, lets send him to login page which redirects to authorize page
	loginToken := makeUUID()
	appStateForFacebookRedirect[loginToken] = safeID
	redirectQueryMap, _ := url.ParseQuery(appState)
	redirectQueryMap.Add("loginToken", loginToken)
	redirectWithQueryString("/web/continueFromExtIdpLogin", redirectQueryMap, w, r)
}

func (s *Service) continueFromExtIdpLogin(w http.ResponseWriter, r *http.Request) {
	// Get the session service from the request context
	sessionService, err := getSessionService(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get the client from the request context
	client, err := getClient(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	queryMap, _ := url.ParseQuery(r.URL.RawQuery)
	loginToken := queryMap["loginToken"][0]

	if loginToken == "" {
		sessionService.SetFlashMessage("login token is not found")
		http.Redirect(w, r, r.RequestURI, http.StatusFound)
		return
	}

	userName := appStateForFacebookRedirect[loginToken]
	if userName == "" {
		sessionService.SetFlashMessage("login token could not be exchanged for email")
		http.Redirect(w, r, r.RequestURI, http.StatusFound)
		return
	}

	// Authenticate the user
	user, err := s.oauthService.FindUserByUsername(userName)
	if err != nil {
		sessionService.SetFlashMessage(err.Error())
		http.Redirect(w, r, r.RequestURI, http.StatusFound)
		return
	}

	// Get the scope string
	scopeStr := r.URL.Query().Get("scope")
	scope, err := s.oauthService.GetScope(scopeStr)
	if err != nil {
		sessionService.SetFlashMessage(err.Error())
		http.Redirect(w, r, r.RequestURI, http.StatusFound)
		return
	}

	// Log in the user
	accessToken, refreshToken, err := s.oauthService.Login(client, user, scope)
	if err != nil {
		sessionService.SetFlashMessage(err.Error())
		http.Redirect(w, r, r.RequestURI, http.StatusFound)
		return
	}

	// Log in the user and store the user session in a cookie
	userSession := &session.UserSession{
		ClientID:     client.Key,
		Username:     user.Username,
		AccessToken:  accessToken.Token,
		RefreshToken: refreshToken.Token,
	}

	if err := sessionService.SetUserSession(userSession); err != nil {
		sessionService.SetFlashMessage(err.Error())
		http.Redirect(w, r, r.RequestURI, http.StatusFound)
		return
	}

	// Redirect to the authorize page by default but allow redirection to other
	// pages by specifying a path with login_redirect_uri query string param
	loginRedirectURI := r.URL.Query().Get("login_redirect_uri")
	if loginRedirectURI == "" {
		loginRedirectURI = "/web/admin"
	}
	redirectWithQueryString(loginRedirectURI, r.URL.Query(), w, r)
}

func getUserInfoFromFacebook(fbAuthCfg config.FacebookAppAuthConfig, code string) (*facebookUserInfo, error) {

	redirectURL := fmt.Sprintf("http://%s:%s/web/fbauthcallback", facebookAuthRedirectHostName, serverListenPort)

	payload := url.Values{}
	payload.Add("client_id", fbAuthCfg.ApplicationID)
	payload.Add("client_secret", fbAuthCfg.ApplicationSecret)
	payload.Add("code", code)
	payload.Add("redirect_uri", redirectURL)

	fmt.Println("Exchanging code for access token")
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "https://graph.facebook.com/v2.12/oauth/access_token?"+payload.Encode(), nil)
	resp, err := client.Do(req)
	fmt.Printf("HTTP status for fetching access code is %s\n", resp.Status)
	if err != nil {
		fmt.Printf("Request to exchange code for access token failed. URL: %s, error: %v \n", req.URL.String(), err)
		return nil, err
	}

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	resultMap := make(map[string]string)
	json.Unmarshal([]byte(bodyString), &resultMap)

	accessToken := resultMap["access_token"]

	fmt.Printf("Getting user's information using access token %s \n", accessToken)
	req, _ = http.NewRequest("GET", fbUserRetrievalURL, nil)
	queryString := req.URL.Query()
	queryString.Add("access_token", accessToken)

	appProof, _ := appSecretProof(fbAuthCfg.ApplicationSecret, accessToken)
	queryString.Add("appsecret_proof", appProof)
	req.URL.RawQuery = queryString.Encode()
	resp, err = client.Do(req)
	fmt.Printf("HTTP status for fetching user information %s\n", resp.Status)
	if err != nil {
		fmt.Printf("Request to get profile using access token failed. URL: %s, error: %v \n", req.URL.String(), err)
		return nil, err
	}

	bodyBytes, _ = ioutil.ReadAll(resp.Body)
	meMap := make(map[string]string)
	json.Unmarshal(bodyBytes, &meMap)

	fbUserInfo := &facebookUserInfo{
		ID:          meMap["id"],
		Name:        meMap["name"],
		Email:       meMap["email"],
		AccessToken: accessToken,
	}

	return fbUserInfo, nil
}

func appSecretProof(appSecret string, accessToken string) (string, error) {
	hash := hmac.New(sha256.New, []byte(appSecret))
	if _, err := hash.Write([]byte(accessToken)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func getLoginLink(fbAppClientID string, stateID string) string {

	redirectURL := fmt.Sprintf("http://%s:%s/web/fbauthcallback", facebookAuthRedirectHostName, serverListenPort)

	fbURL, _ := url.Parse("https://www.facebook.com/v2.11/dialog/oauth")
	parameters := url.Values{}
	parameters.Add("client_id", fbAppClientID)
	parameters.Add("redirect_uri", redirectURL)
	parameters.Add("state", stateID)
	parameters.Add("response_type", "code")
	parameters.Add("scope", "email,public_profile")
	fbURL.RawQuery = parameters.Encode()
	loginLink := fbURL.String() //+ "&redirect_uri=" + redirectURL
	return loginLink
}

func getErrorHTML(errorMsg string) string {
	errTemplateFilePath := "./web/custom/error_msg.html"
	errTemplateBytes, err := ioutil.ReadFile(errTemplateFilePath)
	errTemplateString := string(errTemplateBytes)

	if err != nil {
		fmt.Printf("Encountered error while reading file %s, error: %v", errTemplateString, err)
		return fmt.Sprintf("<html> Error teplate file could not fetched.<br/>Custom error: %s<html>", errorMsg)
	}

	errString := strings.Replace(errTemplateString, "{{error_message}}", errorMsg, 1)
	return errString
}

func jsonMarshal(v interface{}, unescape bool) ([]byte, error) {
	b, err := json.Marshal(v)

	if unescape {
		b = bytes.Replace(b, []byte("\\u003c"), []byte("<"), -1)
		b = bytes.Replace(b, []byte("\\u003e"), []byte(">"), -1)
		b = bytes.Replace(b, []byte("\\u0026"), []byte("&"), -1)
	}
	return b, err
}

func makeUUID() (s string) {
	bytes := make([]byte, 8)
	_, _ = rand.Read(bytes)
	str := fmt.Sprintf("%x", bytes)
	return str
}
