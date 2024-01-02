package main

import (
	"database/sql"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	ID       string
	Username string
	Email    string
	pswdHash string
	Active   string
}

var db *sql.DB

var store = sessions.NewCookieStore([]byte("123456"))

func init() {
	store.Options.HttpOnly = true
	store.Options.Secure = true
	gob.Register(&User{})
}

func main() {
	router := gin.Default()
	router.LoadHTMLGlob("templates/*.html")
	var err error
	db, err = sql.Open("mysql", "root:123456@tcp(localhost:3306)/demo-go")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	authRouter := router.Group("/user", auth)

	router.GET("/", indexHandler)
	router.GET("/login", loginGEThandler)
	router.POST("/login", loginPOSThandler)
	router.GET("/register", registerGETHandler)
	router.POST("/register", registerPOSTHandler)

	authRouter.GET("/profile", profileHandler)

	err = router.Run("localhost:8080")
	if err != nil {
		log.Fatal(err)
	}
}

// auth middleware
func auth(c *gin.Context) {
	fmt.Println("auth middleware running")
	session, _ := store.Get(c.Request, "session")
	_, ok := session.Values["user"]
	if !ok {
		c.HTML(http.StatusForbidden, "login.html", nil)
		c.Abort()
		return
	}
	fmt.Println("middleware done")
	c.Next()
}

// index page
func indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

// loginGEThandler displays form for login
func loginGEThandler(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

// loginPOSThandler verifies login credentials
func loginPOSThandler(c *gin.Context) {
	var user User
	user.Username = c.PostForm("username")
	password := c.PostForm("password")
	err := user.getUserByUsername()
	if err != nil {
		fmt.Println("error selecting pswd_hash in db by Username, err:", err)
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"message": "check username and password"})
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.pswdHash), []byte(password))
	fmt.Println("err from bycrypt:", err)
	if err == nil {
		session, _ := store.Get(c.Request, "session")
		session.Values["user"] = user
		session.Save(c.Request, c.Writer)
		c.HTML(http.StatusOK, "loggedin.html", gin.H{"username": user.Username})
		return
	}
	c.HTML(http.StatusUnauthorized, "login.html", gin.H{"message": "check username and password"})
}

// profileHandler displays profile information
func profileHandler(c *gin.Context) {
	session, _ := store.Get(c.Request, "session")
	var user = &User{}
	val := session.Values["user"]
	var ok bool
	if user, ok = val.(*User); !ok {
		fmt.Println("was not of type *User")
		c.HTML(http.StatusForbidden, "login.html", nil)
		return
	}
	c.HTML(http.StatusOK, "profile.html", gin.H{"user": user})
}

func (u *User) getUserByUsername() error {
	stmt := "SELECT * FROM users WHERE username = ?"
	row := db.QueryRow(stmt, u.Username)
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.pswdHash, &u.Active)
	if err != nil {
		fmt.Println("getUser() error selecting User, err:", err)
		return err
	}
	return nil
}
func registerGETHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", nil)
}
func registerPOSTHandler(c *gin.Context) {
	var user User
	user.Username = c.PostForm("username")
	user.Email = c.PostForm("email")
	password := c.PostForm("password")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Error hashing password:", err)
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{"message": "Error creating user account"})
		return
	}
	user.pswdHash = string(hashedPassword)
	user.Active = "true"
	stmt := "INSERT INTO users (username, email, password_hash, active) VALUES (?, ?, ?, ?)"
	_, err = db.Exec(stmt, user.Username, user.Email, user.pswdHash, user.Active)
	if err != nil {
		fmt.Println("Error creating new user:", err)
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{"message": "Error creating user account"})
		return
	}
	c.Redirect(http.StatusSeeOther, "/login")
}
