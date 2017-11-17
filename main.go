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

)

type Organization struct {
	Id           uint                    `json:"id,omitempty"`
	Name         string                  `json:"name,omitempty"`
	AddressLine1 string                  `json:"addressline1,omitempty"`
	AddressLine2 string                  `json:"addressline2,omitempty"`
	City         string                  `json:"city,omitempty"`
	State        string                  `json:"state,omitempty"`
	Country      string                  `json:"country,omitempty"`
}

func (Organization) TableName() string {
	return "x_org_ext"
}

type User struct {
	Id           uint                   `json:"id,omitempty"`
	FirstName    string                 `json:"firstname,omitempty"`
	LastName     string                 `json:"lastname,omitempty"`
	Email        string                 `json:"email,omitempty"`
	Password     string                 `json:"password,omitempty"`
	PhoneNumber  string                 `json:"phonenumber,omitempty"`
	AddressLine1 string                 `json:"addressline1,omitempty"`
	AddressLine2 string                 `json:"addressline2,omitempty"`
	UserType     string                 `json:"usertype,omitempty"`
	OrgId        uint                   `json:"orgid,omitempty"`
}

func (User) TableName() string {
	return "x_user"
}

type Product struct {
	ID                 uint           `json:"id"`                    // id
	Name               string         `json:"name"`                  // name
	DescText           string         `json:"desc_text"`             // desc_text
	Type               string         `json:"pri_demo_id"`           // type

}

func (Product) TableName() string {
	return "x_prod"
}

type UserClaims struct {
	UserProfile         User            `json:"userprofile"`
	SecretKey              time.Time
	jwt.StandardClaims
}

type Token struct {
	Token  string                      `json:"token"`
}

type Datastruct struct {                                                 //for JSON Formatting
	StatusCode string            `json:"statuscode"`
	Response   interface{}       `json:"response"`
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

func initDb(dbName string) *gorm.DB{
	var db *gorm.DB
	db,err=gorm.Open("mysql","root:password@/"+dbName+"?charset=utf8&parseTime=True&loc=Local")

	if err!=nil {
		log.Fatal(err)
	}

	err = db.DB().Ping()
	if err != nil {
		log.Fatal(err)
		return nil
	}else{
		fmt.Println("connected")
		return db
	}

}

func main() {
	db:=initDb("xshowroom_auth")
	defer db.Close()

	initKeys()

	r:=gin.Default()
	r.POST("/login", login)

	group:=r.Group("/api/v1/")

	group.Use(authMiddleWare())
	{
		group.GET("products", getProducts)
		group.GET("users", getUsers)
		group.POST("users", createUsers)
		group.GET("organisation", getOrg)
		group.POST("organisation", createOrg)
	}
	r.Run(":8080")
}

func login(c *gin.Context){

	//getting credentials from headers
	name1:=c.Request.Header.Get("username")
	pwd1:=c.Request.Header.Get("password")

	fmt.Println("FORM RETURNS ::",name1,pwd1)

	db:=initDb("xshowroom_auth")
	defer db.Close()

	//validate user credentials
	var user []User
	db.Model(User{}).Find(&user)

	flag:=-1                                                            //exit condition
	for _,v:=range user{

		if strings.ToLower(name1) == v.Email && bcrypt.CompareHashAndPassword([]byte(v.Password),[]byte(pwd1))==nil{
			//set claims
			claims = UserClaims{
				User{Id:v.Id,FirstName:v.FirstName,LastName:v.LastName,UserType:v.UserType,OrgId:v.OrgId},
				time.Now(),                       //to generate unique token everytime  //rand.Intn(10000),
				jwt.StandardClaims{
					Issuer: "testing_administrator",
				},
			}

			token := jwt.NewWithClaims(jwt.SigningMethodRS256,claims)
			ss, err := token.SignedString(SignKey)

			if err != nil {
				c.String(404,"Not Found")
				fmt.Fprintln(c.Writer,err)
				log.Printf("err: %+v\n", err)
				return
			}

			c.Writer.Header().Set("status","200")
			response := Token{ss}
			JsonResponse(response,"200 OK",c.Writer)
			flag=1
			return
		}else {
			flag=-1
		}
	}
	if flag==-1{
		fmt.Println("Error Logging in")
		c.AbortWithStatusJSON(401,"Error Logging in")
	}
}

func authMiddleWare() gin.HandlerFunc {
	return func(context *gin.Context) {
		//validate token
		token, err := jwtreq.ParseFromRequestWithClaims(context.Request, jwtreq.AuthorizationHeaderExtractor,&claims,func(token *jwt.Token) (interface{}, error){
			return VerifyKey, nil
		})

		if err == nil && token.Valid{
			fmt.Println("VERIFIED Logged In !")
			context.Next()
		} else {
			JsonResponse("Unauthorized Access","401",context.Writer)
			context.Abort()
		}
	}
}

func getProducts(c *gin.Context){

	db:=initDb("xshowroom_auth")
	defer db.Close()

	var org Organization
	db.Debug().Model(&Organization{}).
		Select("DISTINCT x_org_ext.name").
		Joins("INNER JOIN x_user ON x_org_ext.id = ?",claims.UserProfile.OrgId).
		Scan(&org)

	dbProd:=initDb(org.Name)
	defer dbProd.Close()

	var products []Product
	dbProd.Model(&Product{}).Find(&products)
	JsonResponse(products,"200",c.Writer)

}

func getUsers(c *gin.Context){
	fmt.Println("type :: ",claims.UserProfile.UserType)

	db:=initDb("xshowroom_auth")
	defer db.Close()

	if claims.UserProfile.UserType=="admin" {
		var users []User
		db.Model(&User{}).Find(&users)
		JsonResponse(users, "200", c.Writer)
	}else {
		JsonResponse("Not an Admin", "401", c.Writer)
	}
}

func getOrg(c *gin.Context){
	fmt.Println("type :: ",claims.UserProfile.UserType)

	db:=initDb("xshowroom_auth")
	defer db.Close()

	if claims.UserProfile.UserType=="admin" {
		var org []Organization
		db.Model(&Organization{}).Find(&org)
		JsonResponse(org, "200", c.Writer)
	}else {
		JsonResponse("Not an Admin", "401", c.Writer)
	}
}

func createUsers(c *gin.Context){

	db:=initDb("xshowroom_auth")
	defer db.Close()

	if claims.UserProfile.UserType=="admin"{
		var user User
		json.NewDecoder(c.Request.Body).Decode(&user)

		bs,_:=bcrypt.GenerateFromPassword([]byte(user.Password),bcrypt.MinCost)
		user.Password=string(bs)

		db.Create(&user)
		JsonResponse("User Record Created","200",c.Writer)
	}else{
		JsonResponse("Not an admin","401",c.Writer)
	}

}

func createOrg(c *gin.Context){

	db:=initDb("xshowroom_auth")
	defer db.Close()

	if claims.UserProfile.UserType=="admin"{
		var org Organization

		json.NewDecoder(c.Request.Body).Decode(&org)

		db.Create(&org)
		fmt.Println(org)

		db.Exec("CREATE DATABASE "+org.Name)

		dbOrg:=initDb(org.Name)
		defer dbOrg.Close()

		dbOrg.CreateTable(&Product{})
		JsonResponse("Organisation Record Created","200",c.Writer)
	}else{
		JsonResponse("No Admin Rights","401",c.Writer)
	}
}

func JsonResponse(response interface{}, status string,w http.ResponseWriter) {

	fmt.Println(response)
	data:=Datastruct{Response:response,StatusCode:status}
	json.NewEncoder(w).Encode(data)

}