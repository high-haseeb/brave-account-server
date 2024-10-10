# Authentication Server

This repository contains a simple authentication server that handles user registration, login, email verification, and password reset.

## Features

- User registration with email verification
- User login
- Password reset functionality
- Token-based email verification
- Token-based password reset

## Prerequisites

- Go (Golang) installed on your system
- A mail server or SMTP credentials for sending emails

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/high-haseeb/brave-account-server
cd brave-account-server
```

### 2. Install Dependencies
Make sure Go is installed and set up correctly on your system. You can verify this by running:
```bash
go version
```

### 3. Environment Variables
The application requires certain environment variables to run. Create a .env file in the root of the project and fill it with the following value
```bash
SERVER_ADDR=<server_addr>
# Email settings
SMTP_HOST=<smtp_host>
SMTP_PORT=<smtp_port>
SMTP_USER=<smtp_user>
SMTP_PASSWORD=<smtp_password>
FROM_EMAIL=<your_email>
```
### 4. Run the server
```bash
go run main.go
```
