package main

import (
	"github.com/jinzhu/gorm"
	"log"
	"fmt"
	_ "database/sql"
	_ "github.com/go-sql-driver/mysql"
	"encoding/json"
	jwtreq "github.com/dgrijalva/jwt-go/request"

	"github.com/gin-gonic/gin"
	"net/http"
	"time"
	jwt "github.com/dgrijalva/jwt-go"
	"strings"
	"crypto/rsa"
	"io/ioutil"
	"golang.org/x/crypto/bcrypt"

	"math/rand"
)

type Organization struct {
	Id           uint
	Name         string
	AddressLine1 string
	AddressLine2 string
	City         string
	State        string
	Country      string
}

func (Organization) TableName() string {
	return "x_org_ext"
}

type User struct {
	Id           uint
	FirstName    string
	LastName     string
	Email        string
	Password     string
	PhoneNumber  string
	AddressLine1 string
	AddressLine2 string
	UserType     string
	OrgId        uint
}

func (User) TableName() string {
	return "x_user"
}

type Product struct {
	ID                 uint           `json:"id"`                    // id
	Name               string         `json:"name"`                  // name
	DescText           string         `json:"desc_text"`             // desc_text
//	OrgID              uint           `json:"org_id"`                // org_id
	Type               string         `json:"pri_demo_id"`           // type

}

func (Product) TableName() string {
	return "x_prod"
}

type UserClaims struct {
	UserProfile         User            `json:"userprofile"`
	SecretKey              int
	jwt.StandardClaims
}

type Token struct {
	Token 	string                      `json:"token"`
}

var claims UserClaims

const (
	privKeyPath = "app.rsa"
	pubKeyPath = "app.rsa.pub"
)

var (
	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey
)

var db *gorm.DB
var err error

func initKeys(){
	var err error

	signBytes, err := ioutil.ReadFile(privKeyPath)

	SignKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err !=nil{
		fmt.Println("key not read")
		return
	}

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)

	VerifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err !=nil{
		fmt.Println("key not read")
		return
	}
}

func main() {

	//todo connect db with gorm
	db_name:="xshowroom_auth"                                                    //cubastion , ford india
	db,err=gorm.Open("mysql","root:password@/"+db_name+"?charset=utf8&parseTime=True&loc=Local")

	if err!=nil {
		log.Fatal(err)
	}

	err = db.DB().Ping()
	if err != nil {
		log.Fatal(err)
	}else{
		fmt.Println("connected")
	}
	defer db.Close()

    initKeys()

	//Create Organization and User tables

	/*db.DropTableIfExists(Organization{},User{})
	db.CreateTable(Organization{},User{})*/


	//todo create routes with gin
	r:=gin.Default()
	r.POST("/login",login)
	r.POST("/auth_middleware",authMiddleware)
	r.GET("/products",fetchProduct)
	// r.Handle("GET","/favicon.ico")
	r.Run()


	//todo on new organization create new db (Organization.Name), with default table (Product) and sample data

	//todo on login return token (jwt)

	//todo on fetch products route
		//1 authenticate using token
		//2 extract user's org id
		//2 fetch products from the db of extracted org id
}

func login(c *gin.Context){

	err:=c.Request.ParseForm()
	if err!=nil{
		fmt.Println("unable to parse form data !")
	}
	name1:=c.PostForm("username")
	pwd1:=c.PostForm("password")
	fmt.Println("FORM RETURNS ::",name1,pwd1)

	var flag int                                                        // =1 , user login success
	//validate user credentials

	var user []User
    db.Model(User{}).Find(&user)
//	json.NewEncoder(c.Writer).Encode(user)

    fmt.Println(user)

	for _,v:=range user{
		if strings.ToLower(name1) == v.Email{
			err:=bcrypt.CompareHashAndPassword([]byte(v.Password),[]byte(pwd1))
			if err!=nil {
				fmt.Println("Error logging in")
				fmt.Fprint(c.Writer, "Invalid credentials")
				flag =1
			}else {
				//set claims
				claims = UserClaims{
					v,
					rand.Intn(10000),
					jwt.StandardClaims{
						Issuer: "testing_administrator", //"test-project"
					},
				}
			}
		}
	}

	fmt.Println("SECRET KEY      !",claims.SecretKey)

	if flag !=1{
		token := jwt.NewWithClaims(jwt.SigningMethodRS256,claims)
		ss, err := token.SignedString(SignKey)

		if err != nil {
			c.String(404,"Not Found")
			fmt.Fprintln(c.Writer,err)
			log.Printf("err: %+v\n", err)
			return
		}

		// create session
		cookie,err:=c.Request.Cookie("session")

		if err!=nil{
			cookie = &http.Cookie{
				Name:  "session",
				Value: ss,
				Expires:time.Now().Add(time.Second*300),
			}
		}else{
			cookie.Value=ss
		}

		http.SetCookie(c.Writer, cookie)

		c.Writer.Header().Set("status","200")
		response := Token{ss}
		JsonResponse(response, c.Writer)

	}

}

func authMiddleware(c *gin.Context){

	//validate token
	token, err := jwtreq.ParseFromRequestWithClaims(c.Request, jwtreq.AuthorizationHeaderExtractor,&claims,func(token *jwt.Token) (interface{}, error){
		return VerifyKey, nil
	})

	if err == nil {

		if token.Valid{
			fmt.Println("VERIFIED !")
			fmt.Fprint(c.Writer, "SUCCESS.....!!")
		} else {
			c.Writer.Header().Set("status","401")
			fmt.Fprint(c.Writer, "Token is not valid")
		}
	} else {
		c.Writer.Header().Set("status","401")
		fmt.Fprint(c.Writer, "Unauthorised access , Error Verifying Token")
	}

}

func fetchProduct(c *gin.Context){

}

func JsonResponse(response interface{}, w http.ResponseWriter) {

	jsondata, err :=  json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsondata)
}

