package rest

import (
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/mmirzaee/userist/models"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"
)

// initial routes and http server
func Serve() {
	httpServerConfig := viper.GetStringMap("http_server")

	r := mux.NewRouter()
	setRoutes(r)
	r.Handle("/auth/login", handlers.LoggingHandler(os.Stdout, http.DefaultServeMux))
	srv := &http.Server{
		Handler: handlers.CORS(
			handlers.AllowedOrigins([]string{"*"}),
			handlers.AllowedMethods([]string{"POST", "OPTIONS", "GET"}),
			handlers.AllowedHeaders([]string{"Content-Type", "X-Requested-With", "x-tenant-id", "Authorization"}),
		)(r),
		Addr: httpServerConfig["host"].(string) + ":" + strconv.Itoa(httpServerConfig["port"].(int)),

		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 30 * time.Second,
		ReadTimeout:  30 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

func interceptor(f func(http.ResponseWriter, *http.Request, AuthorizedUser, int), checkAuth bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addDefaultHeaders(w)

		u := AuthorizedUser{}
		t := 0

		// Check Auth
		if checkAuth {
			user, err := checkAuthentication(r)
			if err != nil {
				jsonHttpRespond(w, nil, err.Error(), http.StatusUnauthorized)
				return
			}
			u = user

			// Check tenant
			tenantID, errBadTenantID := strconv.Atoi(r.Header.Get("x-tenant-id"))
			if errBadTenantID != nil || tenantID <= 0 {
				jsonHttpRespond(w, nil, "x-tenant-id header is not set", http.StatusForbidden)
				return
			}
			t = tenantID
		}

		logConfig := viper.GetStringMap("log")
		if logConfig["enable_http_requests_log"] == true {
			requestDump, err := httputil.DumpRequest(r, true)
			if err != nil {
				log.Error(err)
			}
			log.Info("Request: \n" + string(requestDump))
		}

		// Call Original
		f(w, r, u, t)

	})
}

func setRoutes(r *mux.Router) {
	r.Handle("/roles", interceptor(getRoles, true)).Methods("GET")
	r.Handle("/tenants", interceptor(getTenants, true)).Methods("GET")
	r.Handle("/tenants", interceptor(postTenants, true)).Methods("POST")
	r.Handle("/tenants/{id}", interceptor(updateTenant, true)).Methods("POST")
	r.Handle("/tenants/{id}", interceptor(deleteTenant, true)).Methods("DELETE")
	r.Handle("/auth/login", interceptor(postAuthLogin, false)).Methods("POST")
	r.Handle("/auth/refresh-token", interceptor(postRefreshToken, true)).Methods("POST")
	r.Handle("/auth/check-token", interceptor(postAuthCheckToken, true)).Methods("POST")
	r.Handle("/users", interceptor(postUsers, true)).Methods("POST")
	r.Handle("/users/{id}", interceptor(postUpdateUser, true)).Methods("POST")
	r.Handle("/users", interceptor(getUsers, true)).Methods("GET")
	r.Handle("/users/{id}", interceptor(getSingleUser, true)).Methods("GET")
	r.Handle("/users/{id}/meta/{key}", interceptor(getSingleUserMeta, true)).Methods("GET")
	r.Handle("/users/{id}/umeta/{key}", interceptor(getSingleUserMeta, true)).Methods("GET")
	r.Handle("/users/{id}/meta/{key}", interceptor(updateSingleUserMeta, true)).Methods("POST")
	r.Handle("/users/{id}/umeta/{key}", interceptor(updateSingleUniqueUserMeta, true)).Methods("POST")
	r.Handle("/users/{id}/permissions", interceptor(updateUserPermissions, true)).Methods("POST")
	r.Handle("/users/{id}/tenants", interceptor(getUserTenants, true)).Methods("GET")
	r.Handle("/users/{id}", interceptor(deleteUser, true)).Methods("DELETE")
	r.Handle("/users/{id}/meta/{key}", interceptor(deleteUserMeta, true)).Methods("DELETE")
	r.Handle("/users/{id}/permissions", interceptor(deleteUserTenantRole, true)).Methods("DELETE")
}

func generateToken(userData TokenData) string {
	jwtConfig := viper.GetStringMap("jwt")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid": userData.UserId,
		"pms": userData.Roles,
		"exp": time.Now().Add(time.Duration(jwtConfig["lifetime"].(int)) * time.Second).Unix(),
		"iat": time.Now().Unix(),
	})

	signingKey := []byte(jwtConfig["secret"].(string))

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(signingKey)

	if err != nil {
		log.Error(err)
	}
	return tokenString
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		log.Error(err)
	}
	return err == nil
}

func hasPermission(user *AuthorizedUser, permission string, tenantID int) bool {
	hasPerm := false
	if user.Type == "user" {
		tenants := user.Permissions.(map[string]interface{})
		tenant, tenantExists := tenants[strconv.Itoa(tenantID)]
		if tenantExists {
			for _, perm := range tenant.([]interface{}) {
				if perm == permission {
					hasPerm = true
				}
			}
		}
	} else if user.Type == "service" {
		for _, perm := range user.Permissions.([]interface{}) {
			if perm.(string) == permission {
				hasPerm = true
			}
		}
	}
	return hasPerm
}

func jsonHttpRespond(w http.ResponseWriter, respond interface{}, error string, status int) {
	w.WriteHeader(status)

	logConfig := viper.GetStringMap("log")
	if logConfig["enable_http_requests_log"] == true {

		if error != "" {
			res, _ := json.Marshal(map[string]string{"error": error})
			log.Error("Status: " + strconv.Itoa(status) + ", Response: " + string(res))
		} else {
			res, _ := json.Marshal(respond)
			log.Info("Status: " + strconv.Itoa(status) + ", Response: " + string(res))
		}
	}

	if error != "" {
		err := json.NewEncoder(w).Encode(map[string]string{"error": error})
		if err != nil {
			log.Error(err.Error())
		}
		return
	}
	err := json.NewEncoder(w).Encode(respond)
	if err != nil {
		log.Error(err.Error())
	}
}

func addDefaultHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

func checkAuthentication(r *http.Request) (AuthorizedUser, error) {
	authHeader := r.Header.Get("Authorization")
	if strings.Contains(authHeader, "Bearer") {
		authHeader = strings.Replace(authHeader, "Bearer", "", -1)
		tokenString := strings.TrimSpace(authHeader)

		// Parse the token
		jwtConfig := viper.GetStringMap("jwt")

		token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
			signingKey := []byte(jwtConfig["secret"].(string))
			return signingKey, nil
		})

		if err != nil {
			log.Error(err)
			return AuthorizedUser{}, err
		}

		if token.Valid {
			claims := token.Claims.(jwt.MapClaims)
			user, err := models.GetUserByID(uint(claims["uid"].(float64)))
			if err != nil {
				log.Error(err)
				return AuthorizedUser{}, err
			}

			return AuthorizedUser{User: *user, Permissions: claims["pms"], Type: "user"}, nil
		}
	} else {
		if viper.IsSet("services_auth_keys") {
			services := viper.Get("services_auth_keys")
			for _, s := range services.([]interface{}) {
				serviceKey := s.(map[interface{}]interface{})["key"].(string)
				if authHeader == serviceKey {
					serviceName := s.(map[interface{}]interface{})["name"].(string)
					servicePerms := s.(map[interface{}]interface{})["permissions"].([]interface{})
					return AuthorizedUser{User: models.User{DisplayName: serviceName, Username: serviceName, Status: 1}, Permissions: servicePerms, Type: "service"}, nil
				}
			}
		}
		return AuthorizedUser{}, errors.New("invalid token")
	}

	return AuthorizedUser{}, errors.New("invalid token")

}
