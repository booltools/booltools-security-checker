package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"os/exec"
)

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("name")

	// CWE-79: XSS - directly writing user input to response without escaping
	fmt.Fprintf(w, "<html><body><h1>Welcome, %s</h1></body></html>", username)
}

func SafeProfileHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("name")

	// SAFE: using html/template for escaping
	tmpl := template.Must(template.New("profile").Parse("<html><body><h1>Welcome, {{.}}</h1></body></html>"))
	tmpl.Execute(w, username)
}

func PingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	// CWE-78: OS command injection
	output, err := exec.Command("ping", "-c", "4", host).Output()
	if err != nil {
		http.Error(w, "ping failed", 500)
		return
	}
	w.Write(output)
}

func DiagHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")

	// CWE-78: direct command execution from user input
	output, _ := exec.Command("sh", "-c", cmd).Output()
	w.Write(output)
}
