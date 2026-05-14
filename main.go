package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	otp "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

var (
	totpSecret   string
	cookieSecret []byte
	cookieMaxAge int64
	issuer       string
	qrASCII      string

	totpSkew    uint
	antiReplay  bool
	usedCounter sync.Map
	replayTTL   int64 = 300
)

func main() {
	cookieSecretStr := os.Getenv("COOKIE_SECRET")
	if cookieSecretStr == "" {
		cookieSecretStr = loadOrGenerateCookieSecret()
	}
	cookieSecret = []byte(cookieSecretStr)

	issuer = os.Getenv("ISSUER")
	if issuer == "" {
		if data, err := os.ReadFile("/etc/hostname"); err == nil {
			issuer = strings.TrimSpace(string(data))
		}
		if issuer == "" {
			host, err := os.Hostname()
			if err != nil || host == "" {
				host = "2FA-Auth"
			}
			issuer = host
		}
	}

	totpSecret = os.Getenv("TOTP_SECRET")
	if totpSecret == "" {
		totpSecret = loadOrGenerateSecret()
	}

	totpSkew = 1
	if s := os.Getenv("TOTP_SKEW"); s != "" {
		if v, err := strconv.ParseUint(s, 10, 32); err == nil {
			totpSkew = uint(v)
		}
	}

	antiReplay = os.Getenv("TOTP_ANTI_REPLAY") != "false"
	if antiReplay {
		go replayCleaner()
	}

	cookieMaxAge = 86400
	if s := os.Getenv("COOKIE_MAX_AGE"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			cookieMaxAge = v
		}
	}
	if cookieMaxAge <= 0 {
		cookieMaxAge = int64(math.MaxInt64)
	}

	otpauthURI := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s", issuer, totpSecret, issuer)
	qr, err := qrcode.New(otpauthURI, qrcode.Medium)
	if err != nil {
		log.Fatalf("failed to generate QR code: %v", err)
	}
	qrASCII = qr.ToSmallString(false)

	log.Printf("=== Scan this QR code with your authenticator app ===")
	for _, line := range strings.Split(strings.TrimSpace(qrASCII), "\n") {
		log.Printf("%s", line)
	}
	log.Printf("=== Or enter secret manually: %s ===", totpSecret)

	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = ":8080"
	}

	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/qr", qrHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/", indexHandler)

	log.Printf("2FA auth service on %s (skew=%d, anti_replay=%v, cookie_max_age=%ds)", listen, totpSkew, antiReplay, cookieMaxAge)
	log.Fatal(http.ListenAndServe(listen, nil))
}

func loadOrGenerateSecret() string {
	secretFile := os.Getenv("SECRET_FILE")
	if secretFile == "" {
		secretFile = "/data/totp-secret"
	}
	if data, err := os.ReadFile(secretFile); err == nil {
		secret := strings.TrimSpace(string(data))
		if secret != "" {
			log.Printf("loaded TOTP secret from %s", secretFile)
			return secret
		}
	}
	secret := generateSecret()
	if err := os.MkdirAll("/data", 0700); err == nil {
		if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0600); err != nil {
			log.Printf("WARNING: failed to persist TOTP secret to %s: %v", secretFile, err)
		} else {
			log.Printf("saved new TOTP secret to %s", secretFile)
		}
	}
	return secret
}

func loadOrGenerateCookieSecret() string {
	secretFile := os.Getenv("COOKIE_SECRET_FILE")
	if secretFile == "" {
		secretFile = "/data/cookie-secret"
	}
	if data, err := os.ReadFile(secretFile); err == nil {
		secret := strings.TrimSpace(string(data))
		if secret != "" {
			log.Printf("loaded cookie secret from %s", secretFile)
			return secret
		}
	}
	secret := hex.EncodeToString(generateRandom(32))
	if err := os.MkdirAll("/data", 0700); err == nil {
		if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0600); err != nil {
			log.Printf("WARNING: failed to persist cookie secret to %s: %v", secretFile, err)
		} else {
			log.Printf("saved new cookie secret to %s", secretFile)
		}
	}
	return secret
}

func generateRandom(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}

func generateSecret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(generateRandom(20))
}

func validateTOTP(code string) bool {
	valid, err := totp.ValidateCustom(code, totpSecret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      totpSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}

func checkReplay(counter int64) bool {
	_, loaded := usedCounter.LoadOrStore(counter, time.Now().Unix()+replayTTL)
	return !loaded
}

func replayCleaner() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()
		usedCounter.Range(func(key, value interface{}) bool {
			if value.(int64) < now {
				usedCounter.Delete(key)
			}
			return true
		})
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("auth_token"); err == nil && cookie != nil {
		if username, valid := verifyToken(cookie.Value); valid {
			log.Printf("cookie valid for %s", username)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	originalURI := r.Header.Get("X-Forwarded-Uri")
	if originalURI == "" {
		originalURI = "/"
	}
	loginURL := fmt.Sprintf("/_auth/login?next=%s", originalURI)
	log.Printf("no valid cookie, redirecting to %s", loginURL)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		code := strings.TrimSpace(r.FormValue("code"))
		if code == "" || !validateTOTP(code) {
			next := r.FormValue("next")
			log.Printf("login failed: invalid code")
			renderLoginForm(w, r.Host, next, "Invalid code, try again")
			return
		}

		counter := time.Now().Unix() / 30
		if antiReplay && !checkReplay(counter) {
			next := r.FormValue("next")
			log.Printf("login failed: replay detected, counter=%d", counter)
			renderLoginForm(w, r.Host, next, "Code already used, wait for next code")
			return
		}

		token := signToken("user", time.Now().Unix()+cookieMaxAge)
		isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token,
			Path:     "/",
			MaxAge:   int(cookieMaxAge),
			HttpOnly: true,
			Secure:   isSecure,
			SameSite: http.SameSiteLaxMode,
		})
		next := r.FormValue("next")
		if next == "" {
			next = "/"
		}
		log.Printf("login success, redirecting to %s", next)
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	next := r.URL.Query().Get("next")
	renderLoginForm(w, r.Host, next, "")
}

func renderLoginForm(w http.ResponseWriter, host, next, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p style="color:#e53e3e;margin:8px 0">` + errMsg + `</p>`
	}
	nextAttr := ""
	if next != "" {
		nextAttr = fmt.Sprintf(`value="%s"`, next)
	}
	fmt.Fprintf(w, loginHTML, host, errHTML, host, nextAttr)
}

func qrHandler(w http.ResponseWriter, r *http.Request) {
	otpauthURI := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s", issuer, totpSecret, issuer)
	png, err := qrcode.Encode(otpauthURI, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "QR generation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<pre style="line-height:1;letter-spacing:2px">
%s
</pre>
<p>Secret: <code>%s</code></p>
`, qrASCII, totpSecret)
}

func signToken(username string, expiresAt int64) string {
	payload := fmt.Sprintf("%s:%d", username, expiresAt)
	mac := hmac.New(sha256.New, cookieSecret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload + ":" + sig))
}

func verifyToken(token string) (string, bool) {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", false
	}
	parts := strings.SplitN(string(data), ":", 3)
	if len(parts) != 3 {
		return "", false
	}
	username, tsStr, sig := parts[0], parts[1], parts[2]

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil || time.Now().Unix() > ts {
		return "", false
	}

	payload := username + ":" + tsStr
	mac := hmac.New(sha256.New, cookieSecret)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", false
	}
	return username, true
}

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>2FA Login - %s</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: #fff; border-radius: 12px; padding: 40px 36px; box-shadow: 0 2px 16px rgba(0,0,0,0.08); max-width: 360px; width: 100%%; text-align: center; }
  h1 { font-size: 22px; margin-bottom: 6px; }
  .sub { color: #666; font-size: 14px; margin-bottom: 20px; }
  input[type=text] { width: 100%%; padding: 12px 16px; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 20px; text-align: center; letter-spacing: 4px; outline: none; font-family: monospace; }
  input[type=text]:focus { border-color: #667eea; }
  button { width: 100%%; padding: 12px; margin-top: 16px; background: #667eea; color: #fff; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; font-weight: 600; }
  button:hover { background: #5a67d8; }
  %s
</style>
</head>
<body>
<div class="card">
  <h1>%s</h1>
  <p class="sub">Enter the 6-digit code from your authenticator app</p>
  <form method="post">
    <input type="hidden" name="next" %s>
    <input type="text" name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="off" autofocus placeholder="000000">
    <button type="submit">Verify</button>
  </form>
</div>
</body>
</html>`
