package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	jwtverifier "github.com/caleblloyd/okta-jwt-verifier-golang"
)

const sock = "/var/run/auth.sock"

type config struct {
	appPostLoginURL     *url.URL      //APP_POST_LOGIN_URL
	appOrigin           string        //computed
	clientID            string        //CLIENT_ID
	clientSecret        string        //CLIENT_SECRET
	cookieDomain        string        //COOKIE_DOMAIN
	cookieDomainCheck   string        //computed
	cookieName          string        //COOKIE_NAME
	issuer              string        //ISSUER
	loginRedirectURL    *url.URL      //LOGIN_REDIRECT_URL
	oktaLoginBaseURLStr string        //computed
	oktaOrigin          string        //computed
	ssoPath             string        //SSO_PATH
	requestTimeout      time.Duration //Default of 5 seconds if no env set
	verifier            *jwtverifier.JwtVerifier
}

var templateCache = make(map[string]*template.Template)
var templateCacheMu = &sync.Mutex{}

type jwtResponse struct {
	AccessToken string `json:"access_token"`
}

func getConfig() *config {
	//Populate config from env vars
	var appPostLoginURL *url.URL
	var err error
	appPostLogin := os.Getenv("APP_POST_LOGIN_URL")
	if appPostLogin != "" {
		appPostLoginURL, err = url.Parse(appPostLogin)
		if err != nil {
			log.Fatalf("APP_POST_LOGIN_URL is not a valid URL, %v", appPostLogin)
		}
	}

	clientID := os.Getenv("CLIENT_ID")
	if clientID == "" {
		log.Fatalln("Must specify CLIENT_ID env variable - Client ID can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.")
	}

	clientSecret := os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatalln("Must specify CLIENT_SECRET env variable - Client Secret be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.")
	}

	issuer := strings.TrimRight(os.Getenv("ISSUER"), "/")
	if issuer == "" {
		log.Fatalln("This is the URL of the authorization server that will perform authentication. All Developer Accounts have a 'default' authorization server. The issuer is a combination of your Org URL (found in the upper right of the console home page) and /oauth2/default. For example, https://dev-1234.oktapreview.com/oauth2/default.")
	}

	audience := os.Getenv("AUDIENCE")
	if audience == "" {
		log.Fatalln("Must specify AUDIENCE env variable - Audience can be found on the 'Settings' tab of the Authorization Server.  The 'default' authorization server uses the audience 'api://default'")
	}

	issuerURL, err := url.Parse(issuer)
	if err != nil {
		log.Fatalf("ISSUER is not a valid URL, %v", issuer)
	}

	loginRedirect := os.Getenv("LOGIN_REDIRECT_URL")
	if loginRedirect == "" {
		log.Fatalln("Must specify LOGIN_REDIRECT_URL env variable - These can be found on the 'General' tab of the Web application that you created earlier in the Okta Developer Console.")
	}
	loginRedirectURL, err := url.Parse(loginRedirect)
	if err != nil {
		log.Fatalf("LOGIN_REDIRECT_URL is not a valid URL, %v", loginRedirect)
	}

	ssoPath := os.Getenv("SSO_PATH")
	if ssoPath == "" {
		ssoPath = "/sso/"
	} else {
		ssoPath = "/" + strings.Trim(ssoPath, "/") + "/"
	}

	cookieDomain := strings.TrimLeft(os.Getenv("COOKIE_DOMAIN"), ".")
	cookieDomainCheck := loginRedirectURL.Hostname()
	if cookieDomain != "" {
		if !urlMatchesCookieDomain(loginRedirectURL, cookieDomain) {
			log.Fatalf("COOKIE_DOMAIN '%v' must be valid for LOGIN_REDIRECT_URL hostname '%v'", cookieDomain, loginRedirectURL.Hostname())
		}
		cookieDomainCheck = cookieDomain
	}

	cookieName := os.Getenv("COOKIE_NAME")
	if cookieName == "" {
		cookieName = "okta-jwt"
	}

	requestTimeOutDuration := time.Duration(5)
	requestTimeOut := os.Getenv("REQUEST_TIMEOUT")
	if requestTimeOut != "" {
		requestTimeoutInt, err := strconv.Atoi(os.Getenv("REQUEST_TIMEOUT"))
		if err != nil {
			log.Println("Unable to parse REQUEST_TIMEOUT env variable, using a default of 5 seconds")
		} else {
			requestTimeOutDuration = time.Duration(requestTimeoutInt)
		}
	}

	appOrigin := loginRedirectURL.Scheme + "://" + loginRedirectURL.Host
	oktaOrigin := issuerURL.Scheme + "://" + issuerURL.Host

	//Initialize validator
	toValidate := map[string]string{}
	toValidate["aud"] = audience
	toValidate["cid"] = clientID

	jwtverifierSetup := jwtverifier.JwtVerifier{
		Issuer:           issuer,
		ClaimsToValidate: toValidate,
	}

	oktaLoginBaseURLStr := issuer + "/v1/authorize" +
		"?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(loginRedirect) +
		"&response_type=code" +
		"&scope=openid profile" +
		"&nonce=123"

	return &config{
		appPostLoginURL:     appPostLoginURL,
		appOrigin:           appOrigin,
		clientID:            clientID,
		clientSecret:        clientSecret,
		cookieDomain:        cookieDomain,
		cookieDomainCheck:   cookieDomainCheck,
		cookieName:          cookieName,
		issuer:              issuer,
		loginRedirectURL:    loginRedirectURL,
		oktaLoginBaseURLStr: oktaLoginBaseURLStr,
		oktaOrigin:          oktaOrigin,
		requestTimeout:      requestTimeOutDuration,
		ssoPath:             ssoPath,
		verifier:            jwtverifierSetup.New(),
	}
}

func main() {
	runServer(getConfig())
}

func runServer(conf *config) {

	//Validate cookie on /auth/validate requests
	http.HandleFunc("/auth/validate", func(w http.ResponseWriter, r *http.Request) {
		validateCookieHandler(w, r, conf)
	})

	//Authorization code callback
	http.HandleFunc(conf.loginRedirectURL.Path, func(w http.ResponseWriter, r *http.Request) {
		callbackHandler(w, r, conf)
	})

	//Refresh check
	http.HandleFunc(conf.ssoPath+"refresh/check", func(w http.ResponseWriter, r *http.Request) {
		refreshCheckHandler(w, r, conf)
	})

	//Refresh done
	http.HandleFunc(conf.ssoPath+"refresh/done", func(w http.ResponseWriter, r *http.Request) {
		refreshDoneHandler(w, r, conf)
	})

	//Error
	http.HandleFunc(conf.ssoPath+"error", func(w http.ResponseWriter, r *http.Request) {
		errorHandler(w, r, conf)
	})

	//Listen on unix socket instead of http
	removeSockIfExists()
	unixListener, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatal(err)
	}
	defer removeSockIfExists()

	if err = os.Chmod(sock, 0666); err != nil {
		log.Fatal(err)
	}

	err = http.Serve(unixListener, nil)
	if err != nil {
		log.Fatalf("Error serving on socket, err: %v", err)
	}
}

//validateCookieHandler calls the okta api to validate the cookie
func validateCookieHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	log.Printf("validateCookieHandler: Start processing request from %s", r.RemoteAddr)
	// initialize headers
	w.Header().Set("X-Auth-Request-Redirect", "")
	w.Header().Set("X-Auth-Request-User", "")

	auth := r.Header.Get("Authorization")
	split := strings.SplitN(auth, " ", 2)
	var tokenvalue string = ""
	if len(split) == 2 && strings.EqualFold(split[0], "bearer") {
		log.Printf("validateCookieHandler: Using bearer token from Authorization header")
		tokenvalue = split[1]
	} else {
		log.Printf("validateCookieHandler: No bearer token, checking for cookie %s", conf.cookieName)
		tokenCookie, err := r.Cookie(conf.cookieName)
		switch {
		case err == http.ErrNoCookie:
			log.Printf("validateCookieHandler: No cookie found, redirecting to login")
			w.Header().Set("X-Auth-Request-Redirect", redirectURL(r, conf, r.Header.Get("X-Okta-Nginx-Request-Uri")))
			w.WriteHeader(http.StatusUnauthorized)
			return
		case err != nil:
			log.Printf("validateCookieHandler: Error parsing cookie, %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		tokenvalue = tokenCookie.Value
		log.Printf("validateCookieHandler: Found cookie, token length: %d", len(tokenvalue))
	}

	log.Printf("validateCookieHandler: Verifying access token")
	jwt, err := conf.verifier.VerifyAccessToken(tokenvalue)

	if err != nil {
		log.Printf("validateCookieHandler: Token verification failed: %v", err)
		w.Header().Set("X-Auth-Request-Redirect", redirectURL(r, conf, r.Header.Get("X-Okta-Nginx-Request-Uri")))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	log.Printf("validateCookieHandler: Token verification successful")

	sub, ok := jwt.Claims["sub"]
	if !ok {
		log.Printf("validateCookieHandler: Claim 'sub' not included in access token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	subStr, ok := sub.(string)
	if !ok {
		log.Printf("validateCookieHandler: Unable to convert 'sub' to string in access token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Printf("validateCookieHandler: Found subject: %s", subStr)

	validateClaimsTemplate := strings.TrimSpace(r.Header.Get("X-Okta-Nginx-Validate-Claims-Template"))
	if validateClaimsTemplate != "" {
		log.Printf("validateCookieHandler: Validating claims with template: %s", validateClaimsTemplate)
		t, err := getTemplate(validateClaimsTemplate)
		if err != nil {
			log.Printf("validateCookieHandler: validateClaimsTemplate failed to parse template: '%v', error: %v", validateClaimsTemplate, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var resultBytes bytes.Buffer
		if err := t.Execute(&resultBytes, jwt.Claims); err != nil {
			claimsJSON, _ := json.Marshal(jwt.Claims)
			log.Printf("validateCookieHandler: validateClaimsTemplate failed to execute template: '%v', data: '%v', error: '%v'", validateClaimsTemplate, claimsJSON, err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resultString := strings.ToLower(strings.TrimSpace(resultBytes.String()))
		log.Printf("validateCookieHandler: Claims validation result: %s", resultString)

		if resultString != "true" && resultString != "1" {
			log.Printf("validateCookieHandler: validateClaimsTemplate template: '%v', result: '%v', sub: '%v'", validateClaimsTemplate, resultString, subStr)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		log.Printf("validateCookieHandler: Claims validation successful")
	}

	setHeaderNames := strings.Split(r.Header.Get("X-Okta-Nginx-Proxy-Set-Header-Names"), ",")
	setHeaderValues := strings.Split(r.Header.Get("X-Okta-Nginx-Proxy-Set-Header-Values"), ",")
	if setHeaderNames[0] != "" && setHeaderValues[0] != "" && len(setHeaderNames) == len(setHeaderValues) {
		log.Printf("validateCookieHandler: Setting custom headers, count: %d", len(setHeaderNames))
		for i := 0; i < len(setHeaderNames); i++ {
			t, err := getTemplate(setHeaderValues[i])
			if err != nil {
				log.Printf("validateCookieHandler: setHeaderValues failed to parse template: '%v', error: %v", setHeaderValues[i], err)
				continue
			}

			var resultBytes bytes.Buffer
			if err := t.Execute(&resultBytes, jwt.Claims); err != nil {
				claimsJSON, _ := json.Marshal(jwt.Claims)
				log.Printf("validateCookieHandler: setHeaderValues failed to execute template: '%v', data: '%v', error: '%v'", setHeaderValues[i], claimsJSON, err)
				continue
			}
			resultString := strings.ToLower(strings.TrimSpace(resultBytes.String()))
			log.Printf("validateCookieHandler: Setting header %s to value: %s", setHeaderNames[i], resultString)
			w.Header().Set(setHeaderNames[i], resultString)
		}
	}

	w.Header().Set("X-Auth-Request-User", subStr)
	log.Printf("validateCookieHandler: Authentication successful for user: %s", subStr)
	w.WriteHeader(http.StatusOK)
}

func callbackHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	log.Printf("callbackHandler: Start processing callback request from %s", r.RemoteAddr)
	//Read auth code from URL Param
	params := r.URL.Query()
	code := params.Get("code")
	ssoErr := params.Get("error")
	log.Printf("callbackHandler: Code present: %t, Error present: %t", code != "", ssoErr != "")

	unsetCookie := &http.Cookie{
		Domain:   conf.cookieDomain,
		Name:     conf.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
	}

	//Redirect if error in param
	if ssoErr != "" {
		log.Printf("callbackHandler: Error in request: %s, redirecting to error page", ssoErr)
		http.SetCookie(w, unsetCookie)
		http.Redirect(w, r, conf.appOrigin+conf.ssoPath+"error?error="+url.QueryEscape(ssoErr), http.StatusTemporaryRedirect)
		return
	}

	//Check for no code and no error to guard against ddos
	if code == "" {
		log.Printf("callbackHandler: No code provided in request, potential DDOS attempt")
		http.SetCookie(w, unsetCookie)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.Printf("callbackHandler: Exchanging code for JWT token")
	jwtStr, err := getJWT(code, conf)
	//Redirect if error getting JWT
	if err != nil {
		log.Printf("callbackHandler: Error in getJWT: %v", err)
		http.SetCookie(w, unsetCookie)
		http.Redirect(w, r, conf.appOrigin+conf.ssoPath+"error?error="+url.QueryEscape(err.Error()), http.StatusTemporaryRedirect)
		return
	}
	log.Printf("callbackHandler: Successfully obtained JWT token of length: %d", len(jwtStr))

	log.Printf("callbackHandler: Verifying JWT token")
	jwt, err := conf.verifier.VerifyAccessToken(jwtStr)
	if err != nil {
		log.Printf("callbackHandler: JWT Validation Error: %v", err)
		http.SetCookie(w, unsetCookie)
		http.Redirect(w, r, conf.appOrigin+conf.ssoPath+"error?error="+url.QueryEscape(err.Error()), http.StatusTemporaryRedirect)
		return
	}
	log.Printf("callbackHandler: JWT token verification successful")

	exp, ok := jwt.Claims["exp"]
	if !ok {
		log.Printf("callbackHandler: Claim 'exp' not included in access token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	expFloat, ok := exp.(float64)
	if !ok {
		log.Printf("callbackHandler: Unable to convert 'exp' to float64")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Printf("callbackHandler: Token expiration time: %s", time.Unix(int64(expFloat), 0))

	//Set cookie if code valid
	cookie := &http.Cookie{
		Domain:   conf.cookieDomain,
		Expires:  time.Unix(int64(expFloat), 0),
		Name:     conf.cookieName,
		Value:    jwtStr,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	log.Printf("callbackHandler: Set authentication cookie, expires: %s", cookie.Expires)

	//Redirect to requested page
	state := params.Get("state")
	if state == "" {
		log.Printf("callbackHandler: No state parameter, using app origin as redirect target")
		state = conf.appOrigin
	}

	log.Printf("callbackHandler: Parsing state URL: %s", state)
	stateURL, err := url.Parse(state)
	if err != nil {
		log.Printf("callbackHandler: state parameter '%v' is not a valid URL: %v", state, err)
		http.Redirect(w, r, conf.appOrigin+conf.ssoPath+"error?error="+url.QueryEscape("Unauthorized"), http.StatusTemporaryRedirect)
		return
	}

	if (stateURL.Scheme != "" || stateURL.Host != "") && !urlMatchesCookieDomain(stateURL, conf.cookieDomainCheck) {
		log.Printf("callbackHandler: state parameter '%v' is not valid for COOKIE_DOMAIN '%v'", state, conf.cookieDomainCheck)
		http.Redirect(w, r, conf.appOrigin+conf.ssoPath+"error?error="+url.QueryEscape("Unauthorized"), http.StatusTemporaryRedirect)
		return
	}

	log.Printf("callbackHandler: Redirecting to: %s", state)
	http.Redirect(w, r, state, http.StatusTemporaryRedirect)
}

func refreshCheckHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	log.Printf("refreshCheckHandler: Start processing request from %s", r.RemoteAddr)
	tokenCookie, err := r.Cookie(conf.cookieName)
	switch {
	case err == http.ErrNoCookie:
		log.Printf("refreshCheckHandler: No Cookie")
		w.WriteHeader(http.StatusUnauthorized)
		return
	case err != nil:
		log.Printf("refreshCheckHandler: Error parsing cookie: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	log.Printf("refreshCheckHandler: Found cookie, token length: %d", len(tokenCookie.Value))

	log.Printf("refreshCheckHandler: Verifying JWT token")
	jwt, err := conf.verifier.VerifyAccessToken(tokenCookie.Value)

	if err != nil {
		log.Printf("refreshCheckHandler: JWT Validation Error: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	log.Printf("refreshCheckHandler: JWT verification successful")

	exp, ok := jwt.Claims["exp"]
	if !ok {
		log.Printf("refreshCheckHandler: Claim 'exp' not included in access token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	expFloat, ok := exp.(float64)
	if !ok {
		log.Printf("refreshCheckHandler: Unable to convert 'exp' to float64")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	
	expiresAt := time.Unix(int64(expFloat), 0)
	timeRemaining := expiresAt.Sub(time.Now().UTC())
	log.Printf("refreshCheckHandler: Token expires at %s, %s remaining", expiresAt, timeRemaining)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if expFloat-float64(time.Now().UTC().Unix()) < (5 * time.Minute).Seconds() {
		log.Printf("refreshCheckHandler: Token expiring soon, redirecting to refresh")
		_, err = io.WriteString(w, redirectURL(r, conf, conf.ssoPath+"refresh/done"))
	} else {
		log.Printf("refreshCheckHandler: Token valid, no refresh needed")
		_, err = io.WriteString(w, "ok")
	}

	if err != nil {
		log.Printf("refreshCheckHandler: error when writing string to output: %v", err)
		return
	}
}

func refreshDoneHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := io.WriteString(w, `
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>SSO Refresh</title>
			<script>
				window.parent.postMessage("ssoRefreshDone", window.location.protocol + "//" + window.location.host);
			</script>
		</head>
		<body>
			SSO Refresh
		</body>
	</html> 
	`)

	if err != nil {
		log.Printf("refreshDoneHandler: error when writing string to output, %v", err)
		return
	}
}

func errorHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	params := r.URL.Query()
	ssoErr := params.Get("error")

	w.WriteHeader(http.StatusUnauthorized)

	_, err := io.WriteString(w, `
	<!DOCTYPE html>
	<html>
		<head>
			<title>Sign-On Error</title>
			<style>
				body {
					width: 35em;
					margin: 0 auto;
					font-family: Tahoma, Verdana, Arial, sans-serif;
				}
				pre {
					border: 1px solid #000;
					padding: 3px;
					background-color: #dedede;
				}
			</style>
		</head>
	<body>
		<h1>Sign-On Error</h1>
		<p>An error occurred with sign-on</p>
		
		<p><strong>Error Details:</strong></p>

		<pre>`+ssoErr+`</pre>
	</body>
	</html>	
	`)

	if err != nil {
		log.Printf("refreshDoneHandler: error when writing string to output, %v", err)
		return
	}
}

//getJWT queries the okta server with an access code.  A valid request will return a JWT access token.
func getJWT(code string, conf *config) (string, error) {
	log.Printf("getJWT: Exchanging code for JWT, timeout: %s", conf.requestTimeout*time.Second)
	client := &http.Client{
		Timeout: time.Second * conf.requestTimeout,
	}

	reqBody := []byte("code=" + url.QueryEscape(code) +
		"&client_id=" + url.QueryEscape(conf.clientID) +
		"&client_secret=" + url.QueryEscape(conf.clientSecret) +
		"&redirect_uri=" + url.QueryEscape(conf.loginRedirectURL.String()) +
		"&grant_type=authorization_code" +
		"&scope=openid profile")

	tokenURL := conf.issuer + "/v1/token"
	log.Printf("getJWT: Preparing request to: %s", tokenURL)
	req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("getJWT: Error creating request: %v", err)
		return "", err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	log.Printf("getJWT: Sending request to token endpoint")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("getJWT: HTTP request failed: %v", err)
		return "", err
	}

	defer resp.Body.Close()
	log.Printf("getJWT: Received response with status: %d", resp.StatusCode)
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("getJWT: Error reading response body: %v", err)
		return "", err
	}

	//200 == authorization succeeded
	if resp.StatusCode == http.StatusOK {
		log.Printf("getJWT: Successfully received token response")
		jsonResponse := &jwtResponse{}
		err = json.Unmarshal(bodyBytes, &jsonResponse)
		if err != nil {
			log.Printf("getJWT: Error unmarshalling JSON response: %v", err)
			return "", err
		}
		log.Printf("getJWT: Successfully parsed token of length: %d", len(jsonResponse.AccessToken))
		return jsonResponse.AccessToken, nil
	}

	bodyStr := string(bodyBytes)
	log.Printf("getJWT: Token request failed with status %d: %s", resp.StatusCode, bodyStr)
	return "", errors.New(bodyStr)
}

func removeSockIfExists() {
	_, err := os.Stat(sock)
	if err == nil {
		err = os.Remove(sock)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func urlMatchesCookieDomain(matchURL *url.URL, cookieDomain string) bool {
	return matchURL.Hostname() == cookieDomain || strings.HasSuffix(matchURL.Hostname(), "."+cookieDomain)
}

func redirectURL(r *http.Request, conf *config, requestURI string) string {
	log.Printf("redirectURL: Building redirect URL for URI: %s", requestURI)
	requestURLStr := requestURI
	requestOriginURL := getRequestOriginURL(r)
	if requestOriginURL == nil {
		log.Printf("redirectURL: redirect will not include origin (missing headers)")
	} else {
		log.Printf("redirectURL: Got origin URL: %s", requestOriginURL.String())
		if urlMatchesCookieDomain(requestOriginURL, conf.cookieDomainCheck) {
			requestURLStr = requestOriginURL.String() + requestURLStr
			log.Printf("redirectURL: Including origin in redirect URL: %s", requestURLStr)
		} else {
			log.Printf("redirectURL: header 'X-Forwarded-Host' hostname '%v' is not valid for COOKIE_DOMAIN '%v'", requestOriginURL.Hostname(), conf.cookieDomainCheck)
			log.Printf("redirectURL: redirect will not include origin")
		}
	}

	if conf.appPostLoginURL != nil {
		log.Printf("redirectURL: Using appPostLoginURL: %s", conf.appPostLoginURL.String())
		appPostLoginStruct := *conf.appPostLoginURL
		appPostLoginURL := &appPostLoginStruct
		q := appPostLoginURL.Query()
		q.Set("state", requestURLStr)
		appPostLoginURL.RawQuery = q.Encode()
		requestURLStr = appPostLoginURL.String()
		log.Printf("redirectURL: Modified redirect URL with appPostLoginURL: %s", requestURLStr)
	}

	finalURL := conf.oktaLoginBaseURLStr + "&state=" + url.QueryEscape(requestURLStr)
	log.Printf("redirectURL: Final redirect URL: %s", finalURL)
	return finalURL
}

func getRequestOriginURL(r *http.Request) *url.URL {
	requestScheme := r.Header.Get("X-Forwarded-Proto")
	requestHost := r.Header.Get("X-Forwarded-Host")
	log.Printf("getRequestOriginURL: X-Forwarded-Proto=%s, X-Forwarded-Host=%s", requestScheme, requestHost)
	
	if requestScheme != "" && requestHost != "" {
		requestOrigin := requestScheme + "://" + requestHost
		log.Printf("getRequestOriginURL: Attempting to parse origin: %s", requestOrigin)
		requestOriginURL, err := url.Parse(requestOrigin)
		if err != nil {
			log.Printf("getRequestOriginURL: headers 'X-Forwarded-Proto' and 'X-Forwarded-Host' form invalid origin '%v': %v", requestOrigin, err)
			return nil
		}
		return requestOriginURL
	}
	log.Printf("getRequestOriginURL: headers 'X-Forwarded-Proto' and/or 'X-Forwarded-Host' not set")
	return nil
}

func getTemplate(templateText string) (*template.Template, error) {
	templateCacheMu.Lock()
	defer templateCacheMu.Unlock()
	t, ok := templateCache[templateText]
	if ok {
		return t, nil
	}
	t, err := template.New("").Funcs(sprig.TxtFuncMap()).Parse(templateText)
	if err != nil {
		return nil, err
	}
	return t, nil
}
