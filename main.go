// main.go
package main

import (
	// "database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	// "github.com/dgrijalva/jwt-go"                 // vulnerable
	// "github.com/denisenkom/go-mssqldb"            // vulnerable
	"github.com/gorilla/mux"                      // safe
)

func serveHTML(w http.ResponseWriter, r *http.Request) {
	file, err := os.Open("index.html")
	if err != nil {
		http.Error(w, "Could not open file", 500)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "text/html")
	io.Copy(w, file)
}

// func dummyDB() {
// 	connString := "sqlserver://username:password@localhost:1433?database=test"
// 	db, err := sql.Open("sqlserver", connString)
// 	if err != nil {
// 		log.Println("DB error:", err)
// 		return
// 	}
// 	defer db.Close()
// }

// func dummyJWT() {
// 	token := jwt.New(jwt.SigningMethodHS256)
// 	tokenString, err := token.SignedString([]byte("secret"))
// 	if err != nil {
// 		log.Println("JWT error:", err)
// 	}
// 	log.Println("Generated token:", tokenString)
// }

func timeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "The time is %s", time.Now().Format(time.RFC3339))
}

func main() {
	fmt.Println("Hello, World!")
	r := mux.NewRouter()
	r.HandleFunc("/", serveHTML)
	r.HandleFunc("/time", timeHandler)
	log.Println("Starting server on :8080")
	http.ListenAndServe(":8080", r)

	// dummyDB()
	// dummyJWT()
}
