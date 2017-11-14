package main

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
	PhoneNumber  string
	AddressLine1 string
	AddressLine2 string
	UserType     string
	OrgId        uint
}

func (User) TableName() string {
	return "x_user"
}

func main() {

	//todo connect db with gorm

	//todo create routes with gin

	//todo on new organization create new db (Organization.Name), with default table (Product) and sample data

	//todo on login return token (jwt)

	//todo on fetch products route
		//1 authenticate using token
		//2 extract user's org id
		//2 fetch products from the db of extracted org id
}
