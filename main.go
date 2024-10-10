package main

import (
	"context"
	"go-account/server"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	SERVER_ADDR := os.Getenv("SERVER_ADDR")

	log.Println("INFO: Initialzing the db")
	server.InitDB()
	srv := &http.Server{
		Addr:         SERVER_ADDR,
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
		Handler:      middleware{http.DefaultServeMux},
	}

	log.Println("INFO: Starting server at ", SERVER_ADDR)
	http.HandleFunc("/user/create", server.CreateUser)
	http.HandleFunc("/user/verify", server.VerifyUser)
	http.HandleFunc("/user/login", server.LoginUser)
	http.HandleFunc("/user/reset", server.PasswordResestUser)
	http.HandleFunc("/user/reset/success", server.PasswordResestUserSucsess)
	srv.ListenAndServe()
}

type middleware struct {
	mux http.Handler
}

func (m middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := context.WithValue(req.Context(), "user", "unknown")
	ctx = context.WithValue(ctx, "__requestStartTimer__", time.Now())
	req = req.WithContext(ctx)

	m.mux.ServeHTTP(rw, req)

	start := req.Context().Value("__requestStartTimer__").(time.Time)
	log.Println("INFO: request duration: ", time.Now().Sub(start))
}
