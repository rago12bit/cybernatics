package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

var password = "hunter2-hardcoded"

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	defer rows.Close()
	out, _ := exec.Command("sh", "-c", "echo "+name).Output()
	fmt.Fprintf(w, "%x %s", md5.Sum(out), password)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { handler(nil, w, r) })
	http.ListenAndServe("0.0.0.0:8080", nil)
}
