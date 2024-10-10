package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"net/http"
	"net/smtp"
	"net/url"
	"regexp"
	"strings"
)

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Secret   string `json:"secret"`
	Token    string `json:"token"`
	Verified bool
}

func PasswordResestUserSucsess(rw http.ResponseWriter, req *http.Request) {
	http.ServeFile(rw, req, "./html/successful.html")
}
func PasswordResestUser(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		type PasswordResestUserStruct struct {
			Email string `json:"email"`
		}
		var user PasswordResestUserStruct
		err := json.NewDecoder(req.Body).Decode(&user)
		if err != nil {
			log.Println("Error: parsing JSON")
			http.Error(rw, "Error: parsing JSON", http.StatusBadRequest)
			return
		}
		if user.Email == "" {
			log.Println("ERROR: All fields must be filled")
			http.Error(rw, "ERROR: All fields must be filled", http.StatusBadRequest)
			return
		}

		if !isValidEmail(user.Email) {
			log.Println("ERROR: Invalid email format")
			http.Error(rw, "ERROR: Invalid email format", http.StatusBadRequest)
			return
		}
		token, err := getUserToken(user.Email)
		checkErr(err)
		baseURL := "http://192.168.107.62:6969/user/reset"
		u, err := url.Parse(baseURL)
		if err != nil {
			log.Println("ERROR: failed to parse base URL:", err)
			return
		}
		query := u.Query()
		query.Set("token", token)
		query.Set("email", user.Email)
		u.RawQuery = query.Encode()
		sendPasswordResetEmail(user.Email, u.String())
		break
	case http.MethodGet:
		http.ServeFile(rw, req, "./html/index.html")
		break
	case http.MethodPut:
		type PasswordResestUserStruct struct {
			Email       string `json:"email"`
			NewPassword string `json:"password"`
			Token       string `json:"token"`
		}

		var user PasswordResestUserStruct
		err := json.NewDecoder(req.Body).Decode(&user)
		if err != nil {
			log.Println("Error: parsing JSON")
			http.Error(rw, "Error: parsing JSON", http.StatusBadRequest)
			return
		}

		if user.Email == "" || user.NewPassword == "" || user.Token == "" {
			log.Println("ERROR: All fields must be filled")
			http.Error(rw, "ERROR: All fields must be filled", http.StatusBadRequest)
			return
		}

		if !isValidEmail(user.Email) {
			log.Println("ERROR: Invalid email format")
			http.Error(rw, "ERROR: Invalid email format", http.StatusBadRequest)
			return
		}
		log.Println(user.Email, user.Token, user.NewPassword)
		err = updateUserPassword(user.Email, user.Token, user.NewPassword)
		checkErr(err)
		rw.WriteHeader(http.StatusOK)
		fmt.Fprintf(rw, "Password for %s updated successfully to %s", user.Email, user.NewPassword)

		break
	}

}
func CreateUser(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		log.Printf("ERROR: Method not allowed\n")
		http.Error(rw, "ERROR: Method not allowed\n", http.StatusMethodNotAllowed)
	}
	var user User
	err := json.NewDecoder(req.Body).Decode(&user)
	if err != nil {
		log.Printf("ERROR: parsing JSON\n")
		http.Error(rw, "Error: parsing JSON", http.StatusBadRequest)
		return
	}

	if user.Name == "" || user.Email == "" || user.Password == "" || user.Secret == "" {
		log.Printf("ERROR: all fields must be filled\n")
		http.Error(rw, "ERROR: All fields must be filled", http.StatusBadRequest)
		return
	}

	if !isValidEmail(user.Email) {
		log.Printf("ERROR: invalid email\n")
		http.Error(rw, "ERROR: Invalid email format", http.StatusBadRequest)
		return
	}

	log.Printf("Received User: %+v\n", user)

	token := generateToken()
	user.Token = token
	user.Verified = false
	res := addUser(user)
	if res == true {
		http.Error(rw, "ERROR: user email already exists", http.StatusBadRequest)
		return
	}
	sendVerificationEmail(user.Email, fmt.Sprintf("http://192.168.107.62:6969/user/verify?token=%s", token))

	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "User %s has been created successfully! A verification email has been sent to %s, please verify the email! \n", user.Name, user.Email)
}

func LoginUser(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "ERROR: Method not allowed\n", http.StatusMethodNotAllowed)
		return
	}

	type LoginUser struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var user LoginUser
	err := json.NewDecoder(req.Body).Decode(&user)
	if err != nil {
		log.Println("Error: parsing JSON")
		http.Error(rw, "Error: parsing JSON", http.StatusBadRequest)
		return
	}
	fmt.Println(user)

	if user.Email == "" || user.Password == "" {
		log.Println("ERROR: All fields must be filled")
		http.Error(rw, "ERROR: All fields must be filled", http.StatusBadRequest)
		return
	}

	if !isValidEmail(user.Email) {
		log.Println("ERROR: Invalid email format")
		http.Error(rw, "ERROR: Invalid email format", http.StatusBadRequest)
		return
	}
	secret, username, err := getUserData(user.Email, user.Password)
	if err != nil {
		log.Println("ERROR: unknown")
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	type Secret struct {
		SecretValue string `json:"secret"`
		Username    string `json:"username"`
	}
	secretJson := Secret{SecretValue: secret, Username: username}

	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "application/json")
	jsonResponse, err := json.Marshal(secretJson)
	if err != nil {
		http.Error(rw, "Failed to encode JSON", http.StatusInternalServerError)
		return
	}
	rw.Write(jsonResponse)
}
func VerifyUser(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(rw, "ERROR: Method not allowed\n", http.StatusMethodNotAllowed)
		return
	}

	// Extract token from query parameters
	token := req.URL.Query().Get("token")
	if token == "" {
		http.Error(rw, "ERROR: Token is required", http.StatusBadRequest)
		return
	}

	verified, err := verifyUser(token)
	if err != nil {
		http.Error(rw, "ERROR: Unable to verify user", http.StatusInternalServerError)
		return
	}

	if !verified {
		http.Error(rw, "ERROR: Invalid or expired token", http.StatusBadRequest)
		return
	}

	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "User has been verified successfully!\n")
}

func isValidEmail(email string) bool {
	var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return emailRegex.MatchString(strings.ToLower(email))
}

func generateToken() string {
	bytes := make([]byte, 32) // 32 bytes token
	_, err := rand.Read(bytes)
	checkErr(err)
	return base64.URLEncoding.EncodeToString(bytes)
}

func sendVerificationEmail(to string, verificationURL string) {
	// WARN: change this to the official mail

	from := os.Getenv("FROM_EMAIL")
	password := os.Getenv("SMTP_PASSWORD")

	// SMTP server configuration
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	message := fmt.Sprintf(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <title>Email Verification</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;}
            .container {width: 100%%; max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);}
            .header {background-color: #4CAF50; color: #ffffff; padding: 20px; text-align: center; border-top-left-radius: 8px; border-top-right-radius: 8px;}
            .header h1 {margin: 0; font-size: 24px;}
            .content {padding: 20px; text-align: center;}
            .content p {font-size: 16px; color: #333333;}
            .button-container {margin-top: 20px;}
            .button {background-color: #4CAF50; color: #ffffff; text-decoration: none; padding: 10px 20px; font-size: 16px; border-radius: 5px; display: inline-block;}
            .button:hover {background-color: #45a049;}
            .footer {padding: 20px; background-color: #f4f4f4; text-align: center; font-size: 14px; color: #888888; border-bottom-left-radius: 8px; border-bottom-right-radius: 8px;}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Verify Your Email Address</h1>
            </div>
            <div class="content">
                <p>Thank you for signing up! Please confirm your email address by clicking the button below:</p>
                <div class="button-container">
                    <a href="%s" class="button">Verify Email</a>
                </div>
                <p>If you didn’t sign up for this account, you can safely ignore this email.</p>
            </div>
            <div class="footer">
                <p>© 2024 Your Company. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>`, verificationURL)

	headers := map[string]string{
		"From":         from,
		"To":           to,
		"Subject":      "Email Verification",
		"MIME-version": "1.0;",
		"Content-Type": "text/html; charset=\"UTF-8\";",
	}

	messageBody := ""
	for k, v := range headers {
		messageBody += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	messageBody += "\r\n" + message

	// Authentication for the SMTP server
	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(messageBody))
	checkErr(err)

	log.Println("INFO: Email Sent Successfully!")
}

func sendPasswordResetEmail(to string, resetURL string) {
	from := os.Getenv("FROM_EMAIL")
	password := os.Getenv("SMTP_PASSWORD")

	// SMTP server configuration
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	// Prepare the email message
	message := fmt.Sprintf(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <title>Password Reset</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;}
            .container {width: 100%%; max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);}
            .header {background-color: #f44336; color: #ffffff; padding: 20px; text-align: center; border-top-left-radius: 8px; border-top-right-radius: 8px;}
            .header h1 {margin: 0; font-size: 24px;}
            .content {padding: 20px; text-align: center;}
            .content p {font-size: 16px; color: #333333;}
            .button-container {margin-top: 20px;}
            .button {background-color: #f44336; color: #ffffff; text-decoration: none; padding: 10px 20px; font-size: 16px; border-radius: 5px; display: inline-block;}
            .button:hover {background-color: #d32f2f;}
            .footer {padding: 20px; background-color: #f4f4f4; text-align: center; font-size: 14px; color: #888888; border-bottom-left-radius: 8px; border-bottom-right-radius: 8px;}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Password Reset Request</h1>
            </div>
            <div class="content">
                <p>We received a request to reset your password. Please click the button below to set a new password:</p>
                <div class="button-container">
                    <a href="%s" class="button">Reset Password</a>
                </div>
                <p>If you didn’t request a password reset, you can safely ignore this email.</p>
            </div>
            <div class="footer">
                <p>© 2024 Your Company. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>`, resetURL)

	headers := map[string]string{
		"From":         from,
		"To":           to,
		"Subject":      "Password Reset Request",
		"MIME-version": "1.0;",
		"Content-Type": "text/html; charset=\"UTF-8\";",
	}

	messageBody := ""
	for k, v := range headers {
		messageBody += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	messageBody += "\r\n" + message

	// Authentication for the SMTP server
	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(messageBody))
	if err != nil {
		log.Fatalf("ERROR: failed to send email: %v", err)
	}

	log.Println("INFO: Password reset email sent successfully!")
}
