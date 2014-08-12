package auth

import (
	"fmt"
	"log"
	"time"
	"bytes"
	"errors"
	"strconv"
	"strings"
	"encoding/base64"
	"net/http"
	"html/template"
	"crypto/tls"
	"github.com/gorilla/securecookie"
        // www.kingsmountain.com/directory/doc/ldap/3.ldap.html
        "github.com/mavricknz/ldap"

)

type Auth struct {
	Host string
	Port uint16
	Members map[string]bool
	Hashkey []byte
	Blockkey []byte
}

type AuthHandler struct {
	Status int
	Message string
	Url string
	Template *template.Template
}

var ErrT *template.Template
var LoginT *template.Template

// TODO: Convert error and login templates to files
// then add their filenames to config file.
// TODO: add css to error and login templates.
func init() {
	var err error
	if ErrT, err = template.New("error").Parse(`<!DOCTYPE html>
<html>
<head><title>{{.Status}} ERROR</title></head>
<body>
<h1>{{.Status}} ERROR - {{.Message}}</h1>
</body>
</html>`); err != nil {
		log.Fatal(err)
	}
	if LoginT, err = template.New("auth").Parse(`<!DOCTYPE html>
<html>
<head><title>{{.Status}} Not Authorized</title></head>
<body>
<div class="login">
<h1>{{.Status}} Not Authorized - {{.Message}}</h1>
<form action="{{.Url}}" method="post">
<label for="netid">NetId: </label>
<input type="text" name="netid" id="netid" value="" placeholder="(Enter your NetID)"><br>
<label for="password">Password: </label>
<input type="password" name="password" id="password" value="" placeholder="(Enter your password)"><br>
<input type="submit" value="Submit">
</form>
</div>
</body>
</html>`); err != nil {
		log.Fatal(err)
	}
}

// New function verifies configuration data
// and creates Auth type from it.
func New(c map[string]string) (Auth, error) {
	server, present := c["ldap-host"] //"ldap.txstate.edu"
	if !present {
		msg := "ERROR: No LDAP server host configuration."
		log.Println(msg)
		return Auth{}, errors.New(msg)
	}
	portStr, present := c["ldap-port"] //"636"
	if !present {
		msg := "ERROR: No LDAP server port configuration."
		log.Println(msg)
		return Auth{}, errors.New(msg)
	}
	var port, err = strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		log.Println("ERROR: Port number configuration issue.", err)
		return Auth{}, err
	}
	// Hashkey authenticates the cookie using HMAC (64bytes)
	hashkeyStr, present := c["securecookie-hashkey"]
	if !present {
		msg := "ERROR: No secure cookie hashkey configuration."
		log.Println(msg)
		return Auth{}, errors.New(msg)
	}
	hashkey := []byte(hashkeyStr)
	// Blockkey encrypts the cookie value (32bytes for AES-256)
	// This is optional and could be set to nil, but we enforce
	// this setting
	blockkeyStr, present := c["securecookie-blockkey"]
	if !present {
		msg := "ERROR: No secure cookie hashkey configuration."
		log.Println(msg)
		return Auth{}, errors.New(msg)
	}
	blockkey := []byte(blockkeyStr)
	membersStr, present := c["ldap-memberof"]
	if !present {
		msg := "ERROR: No LDAP MemberOf role configuration."
		log.Println(msg)
		return Auth{}, errors.New(msg)
	}
	membersArr := strings.Split(membersStr, ";")
	members := map[string]bool{}
	for _, member := range membersArr {
		member = strings.TrimSpace(member)
		if member != "" {
			members[member] = true
		}
	}
	if len(members) == 0 {
		msg := "ERROR: Empty LDAP MemberOf role configuration."
		log.Println(msg)
		return Auth{}, errors.New(msg)
	}
	return Auth{
		// LDAP verification
		Host: server,
		Port: uint16(port),
		Members: members,
		// secure cookie verification
		Hashkey: hashkey,
		Blockkey: blockkey,
	}, nil
}

func (ah *AuthHandler) Error() string {
	return fmt.Sprintf("%d - %s", ah.Status, ah.Message)
}

func (ah *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ah.Url = CurrentUrl(r)
	var buf bytes.Buffer
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(ah.Status)
	if err := ah.Template.Execute(&buf, ah); err != nil {
		// Not much else we can do here
		// other than log the error
		log.Println(err)
		return
	}
	fmt.Fprintln(w, &buf)
}

func NewHandler(s int, m string, t *template.Template) *AuthHandler {
	return &AuthHandler{Status: s, Message: m, Template: t}
}

func ValidNetId(netid string) bool {
        if len(netid) == 0 {
                return false
        }
        for _, v := range netid {
                switch {
                case v >= '0' && v <= '9':
                case v == '-' || v == '_':
                case v >= 'a' && v <= 'z':
                default:
                        return false
                }
        }
        return true
}

func CurrentUrl(r *http.Request) string {
	var url bytes.Buffer
	url.WriteString(r.URL.Path)
	if r.URL.RawQuery != "" {
		url.WriteString("?")
		url.WriteString(r.URL.RawQuery)
	}
	if r.URL.Fragment != "" {
		url.WriteString("#")
		url.WriteString(r.URL.Fragment)
	}
	return url.String()
}

type AuthSecureCookie struct {
	*securecookie.SecureCookie
}

func (sc *AuthSecureCookie) SetCookie(w http.ResponseWriter, netid string) {
	value := map[string]string{"netid": netid}
	if encoded, err := sc.Encode("site-session", value); err == nil {
		cookie := &http.Cookie{
			Name: "site-session",
			Value: encoded,
			Path: "/",
			Secure: true,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
	}
}

// TODO: Refactor Login into smaller methods like VerifyCookie, VerifyLDAP,...
func (a Auth) Login(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	        var netid string
	        var pwd string
		// Verify that session is valid:
		//   http://www.gorillatoolkit.org/pkg/securecookie
		sc := AuthSecureCookie{securecookie.New(a.Hashkey, a.Blockkey)}
		if cookie, err := r.Cookie("site-session"); err == nil {
			value := make(map[string]string)
			if err = sc.Decode("site-session", cookie.Value, &value); err == nil {
				netid = value["netid"]
				// Reset securecookie before it expires
				sc.SetCookie(w, netid)
				h.ServeHTTP(w, r)
				return
			}
		}
		// Collect credentials from BASIC AUTH if available
		var basicauth []string
		if _, ok := r.Header["Authorization"]; ok {
			basicauth = strings.SplitN(r.Header["Authorization"][0], " ", 2)
		} else {
			basicauth = []string{""}
		}
		if basicauth[0] == "Basic" {
			if len(basicauth) != 2 {
				NewHandler(
					http.StatusBadRequest,
					"Bad Basic Authentication syntax.",
					LoginT).ServeHTTP(w, r)
				return
			}
			payload, _ := base64.StdEncoding.DecodeString(basicauth[1])
			pair := strings.SplitN(string(payload), ":", 2)
			if len(pair) != 2 {
				NewHandler(
					http.StatusBadRequest,
					"Bad Basic Authentication syntax.",
					LoginT).ServeHTTP(w, r)
				return
			}
			netid = strings.ToLower(strings.TrimSpace(pair[0]))
			pwd = strings.TrimSpace(pair[1])
		} else { // Collect credentials from POST
			netid = strings.ToLower(strings.TrimSpace(r.FormValue("netid")))
			pwd = strings.TrimSpace(r.FormValue("password"))
		}
		if netid == "" {
			log.Println("No netid found.")
			NewHandler(
				http.StatusUnauthorized,
				"Please login.",
				LoginT).ServeHTTP(w, r)
			return
		}
		// Validate NetId syntax for valid characters and not empty
		if !ValidNetId(netid) {
			log.Println("invalid netid format.")
			NewHandler(
				http.StatusUnauthorized,
				"Invalid netid characters.",
				LoginT).ServeHTTP(w, r)
			return
		}
		// Verify credentials via LDAP
		log.Printf("Verifying credentials via LDAP: '%s'\n", netid)
		l := ldap.NewLDAPSSLConnection(a.Host, a.Port, &tls.Config{ServerName: a.Host})
		l.NetworkConnectTimeout = 4 * time.Second
		l.ReadTimeout = 4 * time.Second
		if err := l.Connect(); err != nil {
			log.Println(err)
			NewHandler(
				http.StatusInternalServerError,
				"Unable to reach authentication server.",
				ErrT).ServeHTTP(w, r)
			return
	        }
	        defer l.Close()

		// If we can bind to the LDAP server then user and password credentials were correct
	        var binddn string = "CN=" + netid + ",ou=Txstate Users,dc=matrix,dc=txstate,dc=edu"
		if err := l.Bind(binddn, pwd); err != nil {
			log.Println(err)
			NewHandler(
				http.StatusUnauthorized,
				"Invalid netid or password.",
				LoginT).ServeHTTP(w, r)
			return
	        }
		// TODO: Verify that they are included in the config file explicitly or
		// DONE: Verify Implicitly they are part of the UG-ETC-Staff
		//   (for bookstore would be "UG-BOOK-Staff,...")
		var basedn = "ou=Txstate Users,dc=matrix,dc=txstate,dc=edu"
	        var filter = "(cn=" + netid + ")"
	        var attributes = []string{"memberOf"}
	        request := ldap.NewSearchRequest(
	                basedn, //Base DN
	                ldap.ScopeWholeSubtree, //Scope
	                ldap.DerefAlways, //DerefAliases,
	                0, //SizeLimit
	                4, //TimeLimit
	                false, //TypesOnly
	                filter, //Filter
	                attributes, //Attributes
	                nil ) //Controls
		sr, err := l.Search(request)
		if err != nil {
			log.Println(err)
			NewHandler(
				http.StatusInternalServerError,
				"Unable to query authentication server.",
				ErrT).ServeHTTP(w, r)
			return
		}
		err = errors.New("User Department Group does not match.")
		Loop:
		for _, v := range sr.Entries {
			// Example of memberOf:
			// "CN=UG-ETC-Staff,OU=Departmental Groups,OU=Groups,OU=TxState Objects,DC=matrix,DC=txstate,DC=edu"
			for _, m := range v.GetAttributeValues("memberOf") {
				if a.Members[m] {
					err = nil
					break Loop
				}
	                }
		}
		if err != nil {
                        log.Println(err)
			NewHandler(
				http.StatusUnauthorized,
				err.Error(),
				LoginT).ServeHTTP(w, r)
                        return
                }

		// LDAP authentication succeeded so store cookie
		sc.SetCookie(w, netid)

		// At this point we have a valid user so call final handler
		h.ServeHTTP(w, r)
	})
}
