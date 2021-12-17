package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var(
	key = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

type User struct {
	Login string `json:"login"`
	Password string `json:"password"`
	IsAdmin  int `json:"is_admin"`
}

// Конструкция
func middleware(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// логика промежуточного ПО log.Println(r.URL.Path)
		f(w, r)
	}
}

type Middleware func(http.HandlerFunc) http.HandlerFunc

func Logger() Middleware {
	return func(f http.HandlerFunc) http.HandlerFunc { // middleware
		return func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			defer func() {
				log.Println(r.URL.Path, time.Since(start))
			}()

			f(w, r)
		}
	}
}

func Admin() Middleware {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := User{"dev_eng", "qewqwe", 0}
			if user.IsAdmin == 0 {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			f(w, r)
		}
	}
}

func Method(m string) Middleware  {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Do middleware things
			if r.Method != m {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			// Call the next middleware/handler in chain
			f(w, r)
		}
	}
}

func Chain(f http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
	for _, m := range middlewares {
		f = m(f)
	}

	return f
}

var upgrader = websocket.Upgrader{
	ReadBufferSize: 1024,
	WriteBufferSize: 1024,
}

func main()  {
	r := mux.NewRouter()
	//route := http.NewServeMux()
	//wd, _ := os.Getwd()
	fs := http.FileServer(http.Dir("./static")) // filepath.Join(wd, "static/")
	fmt.Println(fs)
	// Serve static files. Файловый сервер если используется gorilla/mux
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := filepath.Join("templates", "chat.html")

		tmpl, _ := template.ParseFiles(p)
		tmpl.Execute(w, nil)
	})

	r.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil) // error ignored for sake of simplicity
		fmt.Println(conn)
		for {
			// Read message from browser
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}

			// Print the message to the console
			fmt.Printf("%s sent: %s\n", conn.RemoteAddr(), string(msg))

			if err = conn.WriteMessage(msgType, msg); err != nil {
				return
			}
		}
	})

	r.HandleFunc("/books/{title}", Chain(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path: %s", r.URL.Path)
	}, Method("POST"), Logger())).Host("www.mybookstore.com") //Ограничьте обработчик запросов определенными именами хостов или поддоменами.

	r.HandleFunc("/books/{title}/page/{page}", Chain(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		title := vars["title"] // the book title slug
		page := vars["page"] // the page

		fmt.Fprintf(w, "You've requested-GET the book: %s on page %s\n", title, page)
	}, Logger(), Admin())).Methods("GET").Schemes("http")

	r.HandleFunc("/books/{title}/page/{page}", Chain(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		title := vars["title"] // the book title slug
		page := vars["page"] // the page

		l := r.FormValue("login")
		p := r.FormValue("password")

		user := User{l, p, 0}

		fmt.Fprintf(w, "You've requested-POST the book: %s on page %s\n", title, page)
		fmt.Fprintf(w, "Data from form: %s on page %s\n", user.Login, user.Password)
	}, Logger())).Methods("POST")

	r.HandleFunc("/form", Chain(func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("templates", "form.html")

		tmpl, _ := template.ParseFiles(path)
		tmpl.Execute(w, nil)
	}, Method("POST"), Logger()))

	r.HandleFunc("/secret", secret)
	r.HandleFunc("/login", login)
	r.HandleFunc("/logout", logout)

	r.HandleFunc("/form-user", func(w http.ResponseWriter, r *http.Request) {
		lp := filepath.Join("templates", "formUser.html")

		tmpl, _ := template.ParseFiles(lp)
		tmpl.Execute(w, nil)
	})

	r.HandleFunc("/decode", func(w http.ResponseWriter, r *http.Request) {
		var user2 User
		var p []byte
		n, _ := r.Body.Read(p)
		fmt.Println(n)
		if n > 0 {
			fmt.Println(string(p))
		}
		fmt.Println("body", r.Body)
		json.NewDecoder(r.Body).Decode(&user2)
		defer r.Body.Close()
		fmt.Println("user-login before", user2)
		withoutHashPass := user2.Password
		hashPass, err := HashPassword(user2.Password)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}
		user2.Password = hashPass
		if CheckPasswordHash(withoutHashPass, user2.Password) {
			fmt.Println(http.StatusText(http.StatusOK))
		}
		fmt.Println("user-login after", user2)


	}).Methods("POST")

	r.HandleFunc("/encode", func(w http.ResponseWriter, r *http.Request) {
		// возвращает поток байт json данных
		user1 := User{"dev_eng", "qweqwe", 1}
		b,_ := json.Marshal(&user1)

		host := "http://localhost:80"
		resource := "/decode"

		// установка параметров в url - строке
		data := url.Values{}
		data.Set("login", user1.Login)
		data.Set("password", user1.Password)

		// создание url для отправки
		u, _ := url.ParseRequestURI(host)
		fmt.Println("u: ", u)
		u.Path = resource
		fmt.Println("u2: ", u)
		urlStr := u.String()
		fmt.Println("u3: ", u)

		client := &http.Client{}
		fmt.Println("DATA", data.Encode())
		r, err := http.NewRequest(http.MethodPost, urlStr, strings.NewReader(string(b))) // 3 объект принимает тип реализующий интерефейс ридер
		if err != nil {
			fmt.Printf("ERROR - %s", err.Error())
		}
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

		res, _ := client.Do(r)
		fmt.Println(res.StatusCode)
	}).Methods("GET")


	log.Fatal(http.ListenAndServe(":80", r))
}

func secret(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")
	fmt.Println(session)

	// Check if user is authenticated
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Print secret message
	fmt.Fprintln(w, "The cake is a lie!")
}

func login(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")
	fmt.Println(session)

	// Authentication goes here
	// ...

	// Set user as authenticated
	session.Values["authenticated"] = true
	session.Save(r, w)
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")
	fmt.Println(session)

	session.Values["authenticated"] = false
	sessions.Save(r, w)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}