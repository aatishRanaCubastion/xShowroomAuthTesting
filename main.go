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

	"strconv"

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
//	OrgID              uint           `json:"org_id"`                // org_id
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

	//todo create routes with gin
	r:=gin.Default()
	r.POST("/login",login)
//	r.POST("/auth_middleware",authMiddleware)
	r.GET("/products",getProducts)
	r.GET("/users",getUsers)
	r.POST("/users",createUsers)
	r.GET("/organisation",getOrg)
	r.POST("/organisation",createOrg)
	r.Run(":8080")
}

func login(c *gin.Context){

	//credentials by headers
	name1:=c.Request.Header.Get("username")
	pwd1:=c.Request.Header.Get("password")

	fmt.Println("FORM RETURNS ::",name1,pwd1)

	var flag int                                                        // =1 , user login success
	//validate user credentials

	var user []User
    db.Model(User{}).Find(&user)

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
					time.Now(),                       //to generate unique token everytime  //rand.Intn(10000),
					jwt.StandardClaims{
						Issuer: "testing_administrator",
					},
				}
			}
		}
	}

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

func authMiddleware(c *gin.Context) (success bool){

	//validate token
	token, err := jwtreq.ParseFromRequestWithClaims(c.Request, jwtreq.AuthorizationHeaderExtractor,&claims,func(token *jwt.Token) (interface{}, error){
		return VerifyKey, nil
	})

	if err == nil {

		if token.Valid{
			fmt.Println("VERIFIED !")
			fmt.Fprint(c.Writer, "SUCCESS.....!!")
			return true
		} else {
			c.Writer.Header().Set("status","401")
			fmt.Fprint(c.Writer, "Token is not valid")
			return false
		}

	} else {
		c.Writer.Header().Set("status","401")
		fmt.Fprint(c.Writer, "Unauthorised access , Error Verifying Token")
		return false
	}
}

func getProducts(c *gin.Context){
	if authMiddleware(c)!=true{
		c.Writer.Header().Set("status","401")
		fmt.Fprint(c.Writer, "Token is not valid")
		return
	}

    var org Organization
	db.Debug().Model(&Organization{}).
		Select("DISTINCT x_org_ext.name").
		Joins("INNER JOIN x_user ON x_org_ext.id = ?",claims.UserProfile.OrgId).
		Scan(&org)

		fmt.Println(org.Name)      //check

	db_prod,err:=gorm.Open("mysql","root:password@/"+org.Name+"?charset=utf8&parseTime=True&loc=Local")

	if err!=nil {
		log.Fatal(err)
	}

	err = db_prod.DB().Ping()
	if err != nil {
		log.Fatal(err)
	}else{
		fmt.Println("connected with DB ::--",org.Name)
	}
	defer db_prod.Close()

	var products []Product
	db_prod.Model(&Product{}).Find(&products)

	JsonResponse(products,c.Writer)
}

func getUsers(c *gin.Context){
	fmt.Println("type :: ",claims.UserProfile.UserType)

	if claims.UserProfile.UserType=="user" || authMiddleware(c)==false{
			c.Writer.Header().Set("status","401")
			fmt.Fprint(c.Writer, "No Admin Rights to View all Users!")

	}else{
		var users []User
		db.Model(&User{}).Find(&users)
		JsonResponse(users,c.Writer)
	}
}

func createUsers(c *gin.Context){

	if claims.UserProfile.UserType=="user" || authMiddleware(c)==false{
		c.Writer.Header().Set("status","401")
		fmt.Fprint(c.Writer, "No Admin Rights to Create Users!")
	}else{
		fname:=c.PostForm("first_name")
		lname:=c.PostForm("last_name")
		email:=c.PostForm("email")
		pwd:=c.PostForm("password")
		phone:=c.PostForm("phone_number")
		add1:=c.PostForm("address_line1")
		add2:=c.PostForm("address_line2")
		utype:=c.PostForm("user_type")
		oid:=c.PostForm("org_id")
		orgid,_:=strconv.Atoi(oid)
		new_user:=User{FirstName:fname,LastName:lname,Email:email,Password:pwd,PhoneNumber:phone,AddressLine1:add1,
		AddressLine2:add2,UserType:utype,OrgId:uint(orgid)}
		db.Create(&new_user)
	}
}

func getOrg(c *gin.Context){
	fmt.Println("type :: ",claims.UserProfile.UserType)

	if claims.UserProfile.UserType=="user" || authMiddleware(c)==false{
		c.Writer.Header().Set("status","401")
		fmt.Fprint(c.Writer, "No Admin Rights to View all Users!")

	}else{
		var org []Organization
		db.Model(&Organization{}).Find(&org)
		JsonResponse(org,c.Writer)
	}
}

func createOrg(c *gin.Context){

	if claims.UserProfile.UserType=="user" || authMiddleware(c)==false{
		c.Writer.Header().Set("status","401")
		fmt.Fprint(c.Writer, "No Admin Rights to Create Users!")
	}else{
		name:=c.PostForm("name")
		add1:=c.PostForm("address_line1")
		add2:=c.PostForm("address_line2")
		city:=c.PostForm("city")
		state:=c.PostForm("state")
		country:=c.PostForm("country")
		new_org:=Organization{Name:name,AddressLine1:add1,AddressLine2:add2,City:city,State:state,Country:country}

		db.Create(&new_org)
		fmt.Println(new_org)

		db_temp, _ := gorm.Open("mysql", "root:password@tcp(127.0.0.1:3306)/")
		db_temp.Exec("CREATE DATABASE "+new_org.Name)

		db_org,err:=gorm.Open("mysql","root:password@tcp(127.0.0.1:3306)/"+new_org.Name+"?charset=utf8&parseTime=True&loc=Local")

		if err!=nil {
			log.Fatal(err)
		}

		err = db_org.DB().Ping()
		if err != nil {
			log.Fatal(err)
		}else{
			fmt.Println("connected with DB ::--",new_org.Name)
		}
		defer db_org.Close()
		db_org.CreateTable(&Product{})
	}
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

