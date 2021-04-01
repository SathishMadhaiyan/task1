package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const (
	COLLECTIONUSER = "user"
	MYSECRETKEY    = "@#@!#$^%"
)

// field names of User struct
type User struct {
	Name     string `json:"name,omitempty" bson:"name,omitempty"`
	Age      int    `json:"age,omitempty" bson:"age,omitempty"`
	Gender   string `json:"gender,omitempty" bson:"gender,omitempty"`
	Status   string `json:"status,omitempty" bson:"status,omitempty"`
	UserName string `json:"username,omitempty" bson:"username,omitempty"`
	Password string `json:"password,omitempty" bson:"password,omitempty"`
}

type AuthCred struct {
	ID   string `json:"id" bson:"id"`
	Pass string `json:"pass" bson:"pass"`
}

type TokenVerify struct {
	Token string `json:"token" bson:"token"`
}

type Response struct {
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

// database is handle to mongoDb database
var db *mongo.Database

// context which carries deadlines, cancellation signals
var ctx context.Context

var Connection redis.Conn

func main() {

	//DB connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// releases resources if slowOperation completes before timeout elapses
	defer cancel()
	/*func() {
		fmt.Println("Calling Cancel")
		cancel()
	}()*/

	// it is used to instantly connect client object into Mongodb
	var client *mongo.Client
	var connectErr error

	if client, connectErr = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017")); connectErr != nil {
		panic("Mongo db not running " + connectErr.Error())
	}

	defer client.Disconnect(ctx)

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		panic("ping err Mongo db not running " + err.Error())
	}

	// it is used to connect client object instantlly to MongoDB
	// Database used to name configuration of database
	db = client.Database("Task")

	var redErr error
	Connection, redErr = redis.Dial("tcp", "localhost:6379")
	if redErr != nil {
		log.Println("not able to connect to redis  - " + redErr.Error())
		return
	}

	// variable will set port number
	port := "8080"

	// Gorilla mux
	// http request multiplexer
	// it used to send a data in URL specipic request router in handler
	route := mux.NewRouter()
	// the handle func register new router which match for the url
	// Login and get Token
	route.HandleFunc("/user", UserInsert).Methods("POST")
	route.HandleFunc("/login", Login).Methods("POST")
	route.HandleFunc("/logout", Logout).Methods("GET")
	//Implementing the Middleware in route
	route.Use(SigninMiddleware)

	router2 := route.NewRoute().Subrouter()
	router2.Use(TokenVerifyMiddleware)
	// Save user
	router2.HandleFunc("/user/reg", UserInsert).Methods("POST")
	router2.HandleFunc("/userupdate", UpdateUser).Methods("PUT")
	router2.HandleFunc("/userdelete/{id}", DeletedUser).Methods("DELETE")
	router2.HandleFunc("/getuser", GetUser).Methods("GET")
	router2.HandleFunc("/enableuser", EnableUser).Methods("PUT")
	// Verify token
	route.HandleFunc("/tokenverify", TokenVerifyHandler).Methods("POST")

	log.Println("Server Running in port " + port)

	// listenand serve listen the tcp network address and accept the connections from http network
	if err := http.ListenAndServe(":"+port, route); err != nil {
		fmt.Println("Cud nt start server due to " + err.Error())
	}

}

func SetValueRedis(key string, value interface{}, expire interface{}) error {

	fmt.Println("set redis key", key)
	//sets data in redis
	_, err := Connection.Do("SET", key, value)
	if err != nil {
		log.Println("not able to set to redis  - " + err.Error())
		return err
	}
	//putting expire
	_, err = Connection.Do("EXPIRE", key, expire)
	if err != nil {
		log.Println("not able to set to redis  - " + err.Error())
		return err
	}
	return nil
}

func GetValueRedis(key string) interface{} {
	// get data from redis
	val, err := Connection.Do("GET", key)
	if err != nil {
		log.Println("not able to get from redis  - " + err.Error())
		return err
	}

	if val == nil {
		log.Println("value nil")
		return nil
	}
	//converting data is string
	return string(val.([]byte))

}

func DeleteAuth(key string) error {

	fmt.Println("Delete redis key", key)

	_, err := Connection.Do("DEL", key)
	if err != nil {
		log.Println("not able to delete to redis  - " + err.Error())
		return err
	}
	return nil
}

// Login user
func Login(w http.ResponseWriter, r *http.Request) {

	var ac AuthCred
	var res Response
	var user User

	// Get from req and put into struct
	if err := json.NewDecoder(r.Body).Decode(&ac); err != nil {
		res.Msg = "Invalid Data - " + err.Error()
		ResponseWriter(w, 400, res)
		return
	}

	// Validate data in Authcred struct
	if ac.ID == "" || ac.Pass == "" {
		res.Msg = "Invalid username or password"
		ResponseWriter(w, 400, res)
		return
	}

	// Validate password
	query := bson.M{"username": ac.ID}

	if err := db.Collection(COLLECTIONUSER).FindOne(ctx, query).Decode(&user); err != nil {
		if err.Error() == "mongo: no documents in result" {
			res.Msg = "Invalid user"
			ResponseWriter(w, 403, res)
			return
		}
		res.Msg = "Internal err - " + err.Error()
		ResponseWriter(w, 500, res)
		return
	}

	fmt.Println("user data", user)

	if ac.Pass != user.Password {
		res.Msg = "Invalid Password"
		ResponseWriter(w, 403, res)
		return
	}

	token, err := CreateJWTToken(user)
	if err != nil {
		res.Msg = "Token generation error " + err.Error()
		ResponseWriter(w, 500, res)
		return
	}

	if err := SetValueRedis(user.UserName, token, 100); err != nil {
		log.Println("redis save err - " + err.Error())
	}
	res.Msg = "Success"
	res.Data = token
	ResponseWriter(w, 200, res)

}

// Logout
func Logout(w http.ResponseWriter, r *http.Request) {

	var res Response

	username := r.URL.Query().Get("username")
	if username == "" {
		res.Msg = "Invalid Data - username is missiong"
		ResponseWriter(w, 400, res)
		return
	}

	if err := DeleteAuth(username); err != nil {
		log.Println("redis save err - " + err.Error())
	}

	res.Msg = "Logout Success"
	ResponseWriter(w, 200, res)
}

// create a user struct
func UserInsert(w http.ResponseWriter, r *http.Request) {

	var user User
	var res Response

	// Get from req and put into struct
	// json.NewDecoder is a decode(unmarshel method of json) and
	// the clients send multiple json objects in the request body into the struct
	// .Decode() used if it encounters any extra unexpected field in the json it returns erro message
	// json key set as string and value whatever
	// json is build a encoder and instanly get text/plain
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		res.Msg = "Invalid Data - " + err.Error()
		// Error function call
		ResponseWriter(w, 400, res)
		return
	}

	query := bson.M{"userName": user.UserName}

	// Check uniqueness of user name
	count, err := db.Collection(COLLECTIONUSER).CountDocuments(ctx, query)
	if err != nil {
		res.Msg = "Internel err - " + err.Error()
		ResponseWriter(w, 500, res)
		return
	}
	// condition check
	if count > 0 {
		res.Msg = "username already exist"
		ResponseWriter(w, 409, res)
		return
	}

	// Insert a user data to db
	result, err := db.Collection("user").InsertOne(ctx, user)
	if err != nil {
		res.Msg = "Internel err - " + err.Error()
		ResponseWriter(w, 500, res)
		return
	}

	// Success response
	res.Msg = "Success"
	res.Data = result
	ResponseWriter(w, 200, res)

}

// Enable user
func EnableUser(w http.ResponseWriter, r *http.Request) {

	var user User
	var res Response

	name := r.URL.Query().Get("name")

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		res.Msg = "Invalid Data - " + err.Error()
		ResponseWriter(w, 400, res)
		return
	}
	// Set the status active in specipic data
	selecter := bson.M{"name": name}
	data := bson.M{"$set": bson.M{"status": "Active"}}

	up, err := db.Collection("user").UpdateOne(ctx, selecter, data)

	if err != nil {
		res.Msg = "Internel err - " + err.Error()
		ResponseWriter(w, 500, res)
		return
	}

	fmt.Println("Data was updated : ", up.ModifiedCount)
	// Success response
	res.Msg = "Success"
	res.Data = user
	ResponseWriter(w, 200, res)

}

// Update user
func UpdateUser(w http.ResponseWriter, r *http.Request) {

	var user User
	var res Response

	name := r.URL.Query().Get("name")

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		res.Msg = "Invalid Data - " + err.Error()
		ResponseWriter(w, 400, res)
		return
	}

	selecter := bson.M{"name": name}
	data := bson.M{"$set": user}

	up, err := db.Collection("user").UpdateOne(ctx, selecter, data)

	if err != nil {
		res.Msg = "Internel err - " + err.Error()
		ResponseWriter(w, 500, res)
		return
	}

	fmt.Println("Data was updated : ", up.ModifiedCount)
	// Success response
	res.Msg = "Success"
	res.Data = user
	ResponseWriter(w, 200, res)

}

// Get user
func GetUser(w http.ResponseWriter, r *http.Request) {

	var res Response
	var user User
	// Platform query use to get data in specific field of User struct
	username := r.URL.Query().Get("username")
	if username == "" {
		res.Msg = "Invalid Data - username is missiong"
		ResponseWriter(w, 400, res)
		return
	}
	// Query generating
	query := bson.M{"username": username}
	if err := db.Collection(COLLECTIONUSER).FindOne(ctx, query).Decode(&user); err != nil {
		res.Msg = "Internal err - " + err.Error()
		ResponseWriter(w, 500, res)
		return
	}

	res.Msg = "Success"
	res.Data = user
	ResponseWriter(w, 200, res)
}

// Delete user
func DeletedUser(w http.ResponseWriter, r *http.Request) {

	var user User
	var res Response
	w.Header().Set("content-type", "applications/json")

	params := mux.Vars(r)

	id, err := primitive.ObjectIDFromHex(params["id"])

	if err != nil {
		res.Msg = "Invalid Id - " + err.Error()
		// Error function call
		ResponseWriter(w, 400, res)
		return
	}

	_, err = db.Collection("user").DeleteOne(ctx, bson.M{"_id": id})

	if err != nil {
		res.Msg = "Invalid Data - " + err.Error()
		// Error function call
		ResponseWriter(w, 500, res)
		return
	}

	// Success response
	res.Msg = "Success"
	res.Data = user
	ResponseWriter(w, 200, res)

	fmt.Println("One data was deleted : ", id)

}

func SigninMiddleware(f http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//Pre
		t := time.Now()
		fmt.Println(t)
		//Handler
		f.ServeHTTP(w, r)
		//Post
		t2 := time.Now()
		fmt.Println("Time taken to excute ", r.URL.Path, t2.Sub(t).Seconds())

	})
}

// HTTP server should be a function that takes in a function that implements the http.Handler interface and
// returns a new function that implements the http.Handler interface.
func TokenVerifyMiddleware(f http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var res Response

		fmt.Println("Middleware 2 start -")
		// This takes the JWT token from the Authorization header.
		token := r.Header.Get("Authorization")

		fmt.Println("token", token)

		claims, ok, err := VerifyToken(token)
		if err != nil {
			res.Msg = "Token verification error - " + err.Error()
			ResponseWriter(w, 403, res)
			return
		}
		if !ok {
			res.Msg = "Un Authorized"
			ResponseWriter(w, 403, res)
			return
		}

		if claims != nil {
			// taking data from the clims
			user := claims["data"].(map[string]interface{})
			fmt.Println(user)
			token := GetValueRedis(user["username"].(string))
			if token == nil {
				res.Msg = "Un Authorized - no token in redis"
				ResponseWriter(w, 403, res)
				return
			}
			fmt.Println("tok ===> GOT", token)

		}

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		f.ServeHTTP(w, r)
		fmt.Println("Middleware 2 Ends....")

	})
}

// Errors function
func ResponseWriter(w http.ResponseWriter, statusCode int, res Response) {
	// send response in json data
	w.Header().Set("Content-Type", "application/json")
	// writeheader sends the status code of http response header and provided status code
	// writeheader mainly used to send the erroer codes
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(res); err != nil {
		w.WriteHeader(500)
		w.Write([]byte("Server error"))
		return
	}
}

// Token generated
func CreateJWTToken(data interface{}) (string, error) {

	// Create the token
	// Hash-based Message Authenticaton Code, e.g. HS256
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	// Set some claims
	token.Claims = jwt.MapClaims{

		"data": data,

		// token expiry time setup
		"exp": time.Now().Add(time.Second * 50).Unix(),
	}
	// Sign and get the complete encoded token as a string
	return token.SignedString([]byte(MYSECRETKEY))
}

func TokenVerifyHandler(w http.ResponseWriter, r *http.Request) {

	var tv TokenVerify
	var res Response

	// Get from req and put into struct
	if err := json.NewDecoder(r.Body).Decode(&tv); err != nil {
		res.Msg = "Invalid Data - " + err.Error()
		ResponseWriter(w, 400, res)
		return
	}

	claims, ok, err := VerifyToken(tv.Token)
	if err != nil {
		res.Msg = "Token verification error " + err.Error()
		ResponseWriter(w, 500, res)
		return
	}

	// check the boolean error
	if !ok {
		res.Msg = "Un aurhorised"
		ResponseWriter(w, 403, res)
		return
	}

	res.Msg = "Success"
	res.Data = claims
	ResponseWriter(w, 200, res)

}

// verify the token
func VerifyToken(token string) (jwt.MapClaims, bool, error) {

	// decode the token into a MapClaims,
	var claims jwt.MapClaims

	// Function jwt.ParseWithClaims accept an interface of jwt.Claims
	tkn, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(MYSECRETKEY), nil
	})

	if err != nil {

		// it mentions that if you're specifying the wrong key to verify against you'll get that error
		if err == jwt.ErrSignatureInvalid {
			return nil, false, nil
		}

		return nil, false, err
	}

	if !tkn.Valid {
		return nil, false, nil
	}

	return claims, true, nil
}
