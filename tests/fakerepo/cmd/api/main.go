package main

import (
	"fmt"
	"net/http"
	"os"
)

const (
	DatabaseHost     = "prod-db.internal.acme.com"
	DatabasePassword = "SuperSecret123!"
	APISecretKey     = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	AWSAccessKey     = "AKIAIOSFODNN7EXAMPLE"
	AWSSecretKey     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/user/", userHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/file", fileHandler)

	fmt.Printf("Server starting on :%s\n", port)
	http.ListenAndServe(":"+port, nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to ACME API"))
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Admin panel - no auth required"))
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Path[len("/user/"):]
	w.Write([]byte("User: " + userID))
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(100 << 20) // 100MB - no file type validation
	file, handler, _ := r.FormFile("file")
	defer file.Close()

	dst, _ := os.Create("/uploads/" + handler.Filename) // path traversal possible
	defer dst.Close()
	w.Write([]byte("Uploaded: " + handler.Filename))
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	data, _ := os.ReadFile(path) // direct path traversal - CWE-22
	w.Write(data)
}
