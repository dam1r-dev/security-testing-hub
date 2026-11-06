// A deliberately vulnerable net/http server: a fixture for the scanner's tests. Do not deploy.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"

	"example.com/vulnerable-go-app/store"
)

var db *sql.DB

// A signing secret written in the code.
var sessionSecret = []byte("change-me-please-123")

// SQL injection: the name goes into the query text.
func searchUsers(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query("SELECT id, email FROM users WHERE name = '" + name + "'")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintln(w, "ok")
}

// SQL injection through fmt.Sprintf.
func deleteItem(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	db.Exec(fmt.Sprintf("DELETE FROM items WHERE id = %s", id))
}

// Safe: the value is passed separately.
func searchSafe(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT id FROM users WHERE name = $1", r.URL.Query().Get("name"))
	defer rows.Close()
}

// Command injection: the host is run through a shell.
func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	w.Write(out)
}

// Path traversal: the file name is used as sent.
func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, err := os.ReadFile("./uploads/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}

// SSRF: the server fetches whatever address it is given.
func preview(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(r.URL.Query().Get("url"))
	if err != nil {
		http.Error(w, "bad gateway", 502)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// Open redirect.
func login(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}

// XSS: the name is written into the page as it is, and a user's bio is marked safe.
func hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}

var profileTemplate = template.Must(template.New("profile").Parse("<div>{{.Bio}}</div>"))

func profile(w http.ResponseWriter, r *http.Request) {
	profileTemplate.Execute(w, map[string]interface{}{"Bio": template.HTML(r.FormValue("bio"))})
}

// The query is built in another package (store/users.go).
func findUser(w http.ResponseWriter, r *http.Request) {
	user := store.FindUserByEmail(r.FormValue("email"))
	fmt.Fprintln(w, user)
}

// Weak crypto and a certificate check switched off.
func hashPassword(password string) []byte {
	sum := md5.Sum([]byte(password))
	return sum[:]
}

func newClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

// A login cookie that scripts can read.
func setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token})
}

func main() {
	http.HandleFunc("/search", searchUsers)
	http.HandleFunc("/delete", deleteItem)
	http.HandleFunc("/safe", searchSafe)
	http.HandleFunc("/ping", ping)
	http.HandleFunc("/download", download)
	http.HandleFunc("/preview", preview)
	http.HandleFunc("/login", login)
	http.HandleFunc("/hello", hello)
	http.HandleFunc("/profile", profile)
	http.HandleFunc("/user", findUser)
	http.ListenAndServe(":8080", nil)
}
