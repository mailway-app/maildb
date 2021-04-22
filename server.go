package main

import (
	"bytes"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/mail"
	"os"
	"path"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/mailway-app/config"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	// Secret token that webhooks set on the email for us
	// Used to validate the /db/email/{uuid} endpoint
	MW_BODY_SECRET_TOKEN = "Mw-Int-Maildb-Secret-Token"
)

var (
	SQLITE_DB string = "./maildb.db"
)

func parseJWT(v string) (*jwt.Token, error) {
	claims := new(jwt.StandardClaims)
	token, err := jwt.ParseWithClaims(v, claims, func(token *jwt.Token) (interface{}, error) {
		return lookupPublicKey()
	})

	if err != nil || !token.Valid {
		return nil, errors.Wrap(err, "key failed to verify")
	}
	if err := token.Claims.Valid(); err != nil {
		return nil, errors.Wrap(err, "JWT claims not valid")
	}

	return token, nil
}

func lookupPublicKey() (interface{}, error) {
	data, err := ioutil.ReadFile(path.Join(config.ROOT_LOCATION, "key.pub"))
	if err != nil {
		return nil, errors.Wrap(err, "could not read key file")
	}
	return jwt.ParseRSAPublicKeyFromPEM(data)
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

const (
	MAIL_STATUS_RECEIVED = 0
	// MAIL_STATUS_PROCESSED = 1
	// MAIL_STATUS_DELIVERED = 2
	// MAIL_STATUS_SPAM      = 3
)

func initDB(db *sql.DB) error {
	sqlStmt := `
		CREATE TABLE mails (
			uuid blob,
			domain varchar(255),
			time datetime,
			status int,
			rule blob,
			` + "`from`" + ` varchar(255),
			` + "`to`" + ` varchar(255)
		);
	`
	_, err := db.Exec(sqlStmt)
	return err
}

func migrateDB(db *sql.DB) error {
	sqlStmt := "ALTER TABLE mails ADD COLUMN `to` varchar(255);"
	_, err := db.Exec(sqlStmt)
	return err
}

type Mail struct {
	Uuid   uuid.UUID
	Domain string
	Time   time.Time
	Status int
	Rule   uuid.UUID
	From   string
	To     string
}

type LogEntry struct {
	Uuid   uuid.UUID `json:"uuid"`
	Time   int64     `json:"time"`
	Status int       `json:"status"`
	Rule   uuid.UUID `json:"rule"`
	From   string    `json:"from"`
	To     string    `json:"to"`
}

func insertMail(db *sql.DB, mail Mail) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("insert into mails(uuid, domain, time, status, `from`) values(?, ?, ?, ?, '')")
	if err != nil {
		return err
	}
	defer stmt.Close()

	uuidBytes, err := mail.Uuid.MarshalBinary()
	check(err)

	_, err = stmt.Exec(uuidBytes, mail.Domain, mail.Time, MAIL_STATUS_RECEIVED)
	if err != nil {
		return err
	}

	check(tx.Commit())

	log.Debugf("inserted mail %s", mail.Uuid)
	return nil
}

func updateMailEnvelope(db *sql.DB, uuid uuid.UUID, field string, value string) error {
	stmt, err := db.Prepare("update mails set `" + field + "`=? where uuid=?")
	if err != nil {
		return err
	}

	uuidBytes, err := uuid.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = stmt.Exec(value, uuidBytes)
	if err != nil {
		return err
	}

	log.Debugf("updated %s %s: %s", uuid, field, value)
	return nil
}

func updateStatusMail(db *sql.DB, uuid uuid.UUID, newStatus int) error {
	stmt, err := db.Prepare("update mails set status=? where uuid=?")
	if err != nil {
		return err
	}

	uuidBytes, err := uuid.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = stmt.Exec(newStatus, uuidBytes)
	if err != nil {
		return err
	}

	log.Debugf("updated status %s to %d", uuid, newStatus)
	return nil
}

func updateRuleMail(db *sql.DB, uuid uuid.UUID, rule uuid.UUID) error {
	stmt, err := db.Prepare("update mails set rule=? where uuid=?")
	if err != nil {
		return err
	}

	uuidBytes, err := uuid.MarshalBinary()
	if err != nil {
		return err
	}

	ruleBytes, err := rule.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = stmt.Exec(ruleBytes, uuidBytes)
	if err != nil {
		return err
	}

	log.Debugf("updated rule %s to %s", uuid, rule)
	return nil
}

func getMailsByDomain(db *sql.DB, domain string) ([]Mail, error) {
	out := make([]Mail, 0)

	stmt, err := db.Prepare("select uuid, time, status, rule, `from`, `to` from mails where domain = ? order by time desc limit 100")
	if err != nil {
		return out, err
	}
	defer stmt.Close()

	rows, err := stmt.Query(domain)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	for rows.Next() {
		var uuidBytes []byte
		var time time.Time
		var status int
		var ruleBytes []byte
		var from string
		var maybeTo sql.NullString
		err = rows.Scan(&uuidBytes, &time, &status, &ruleBytes, &from, &maybeTo)
		if err != nil {
			return out, err
		}

		id := uuid.Nil
		check(id.UnmarshalBinary(uuidBytes))

		rule := uuid.Nil
		if len(ruleBytes) > 0 {
			check(rule.UnmarshalBinary(ruleBytes))
		}

		to := ""
		if maybeTo.Valid {
			to = maybeTo.String
		}

		out = append(out, Mail{
			Uuid:   id,
			Domain: domain,
			Time:   time,
			Status: status,
			Rule:   rule,
			From:   from,
			To:     to,
		})
	}
	err = rows.Err()
	if err != nil {
		return out, err
	}

	return out, nil
}

func getDomains(db *sql.DB) ([]string, error) {
	out := make([]string, 0)

	stmt, err := db.Prepare("select distinct domain from mails")
	if err != nil {
		return out, err
	}
	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		return out, err
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		err = rows.Scan(&domain)
		if err != nil {
			return out, err
		}
		out = append(out, domain)
	}
	err = rows.Err()
	if err != nil {
		return out, err
	}

	return out, nil
}

func main() {
	if err := config.Init(); err != nil {
		log.Fatalf("failed to init config: %s", err)
	}

	var db *sql.DB
	defer db.Close()

	if config.CurrConfig.MaildbPath != "" {
		SQLITE_DB = config.CurrConfig.MaildbPath
	}

	if fileExists(SQLITE_DB) {
		var err error
		db, err = sql.Open("sqlite3", SQLITE_DB)
		check(err)
		if err = migrateDB(db); err != nil {
			log.Infof("migrateDB: %s", err)
		}
	} else {
		var err error
		db, err = sql.Open("sqlite3", SQLITE_DB)
		check(err)
		check(initDB(db))
	}

	r := mux.NewRouter()
	handler := MailDB{db}

	r.HandleFunc("/db/domains", handler.GetDomains).Methods("GET")
	r.HandleFunc("/db/domain/{domain}/new/{uuid}", handler.RecordDomainMail).Methods("POST")
	r.HandleFunc("/db/domain/{domain}/update/{uuid}", handler.UpdateDomainMail).Methods("PUT")
	r.HandleFunc("/db/domain/{domain}/logs", handler.GetDomainLogs).Methods("GET")
	r.HandleFunc("/db/domain/{domain}/aliases", handler.GetDomainAliases).Methods("GET")
	r.HandleFunc("/db/email/{uuid}", handler.GetEmail).Queries("token", "{token}").Methods("GET")
	http.Handle("/", r)
	if !config.CurrConfig.IsInstanceLocal() {
		r.Use(authMiddleware)
	}
	r.Use(loggingMiddleware)

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:8081",
		WriteTimeout: 5 * time.Second,
		ReadTimeout:  5 * time.Second,
	}

	log.Infof("listening on %s (in mode %s)", srv.Addr, config.CurrConfig.InstanceMode)
	log.Fatal(srv.ListenAndServe())
}

type MailDB struct {
	db *sql.DB
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Infof("%s %s\n", r.Method, r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/db/email/") {
			next.ServeHTTP(w, r)
			return
		}
		authorization := r.Header.Get("Authorization")
		if authorization == "" {
			log.Warn("missing JWT token")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		token := strings.ReplaceAll(authorization, "Bearer ", "")
		if _, err := parseJWT(token); err != nil {
			log.Errorf("JWT token not valid: %s", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h MailDB) GetDomainLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := vars["domain"]

	mails, err := getMailsByDomain(h.db, domain)
	check(err)

	out := make([]LogEntry, len(mails))
	for i, mail := range mails {
		out[i] = LogEntry{
			Uuid:   mail.Uuid,
			Time:   mail.Time.Unix() * 1000,
			Status: mail.Status,
			Rule:   mail.Rule,
			From:   mail.From,
			To:     mail.To,
		}
	}

	json, err := json.Marshal(out)
	check(err)

	w.WriteHeader(http.StatusOK)
	w.Write(json)
}

func (h MailDB) GetDomainAliases(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := vars["domain"]

	mails, err := getMailsByDomain(h.db, domain)
	check(err)

	set := make(map[string]bool)

	for _, row := range mails {
		tos, err := mail.ParseAddressList(row.To)
		if err != nil {
			log.Warnf("failed to parse address: %s", err)
			continue
		}

		for _, to := range tos {
			if strings.HasSuffix(to.Address, domain) {
				set[to.Address] = true
			}
		}
	}

	out := make([]string, len(set))
	i := 0
	for value, _ := range set {
		out[i] = value
		i++
	}

	json, err := json.Marshal(out)
	check(err)

	w.WriteHeader(http.StatusOK)
	w.Write(json)
}

func (h MailDB) GetEmail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["uuid"]

	file := fmt.Sprintf("/usr/local/lib/maildb/%s.eml", id)
	data, err := ioutil.ReadFile(file)
	if err != nil {
		log.Infof("could not read email: %s", err)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("email not found"))
		return
	}

	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		log.Errorf("failed to parse message: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("unknown internal server error"))
		return
	}

	secretToken := []byte(msg.Header.Get(MW_BODY_SECRET_TOKEN))
	actual := []byte(r.FormValue("token"))
	if subtle.ConstantTimeCompare(secretToken, actual) == 0 {
		log.Info("token is not valid")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("token mismatch"))
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, msg.Body); err != nil {
		log.Errorf("could not send mail in response: %s", err)
	}
}

func (h MailDB) RecordDomainMail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	uuid := uuid.Nil
	check(uuid.UnmarshalText([]byte(vars["uuid"])))

	mail := Mail{
		Uuid:   uuid,
		Domain: vars["domain"],
		Time:   time.Now().UTC(),
	}
	check(insertMail(h.db, mail))

	out, err := json.Marshal(mail)
	check(err)

	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

type UpdateDomain struct {
	Status *int    `json:"status"`
	From   *string `json:"from"`
	To     *string `json:"to"`
	Rule   *string `json:"rule"`
}

func (h MailDB) UpdateDomainMail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	id := uuid.Nil
	check(id.UnmarshalText([]byte(vars["uuid"])))

	var update UpdateDomain

	err := json.NewDecoder(r.Body).Decode(&update)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if update.Status != nil {
		check(updateStatusMail(h.db, id, *update.Status))
	}

	if update.From != nil {
		check(updateMailEnvelope(h.db, id, "from", *update.From))
	}

	if update.To != nil {
		check(updateMailEnvelope(h.db, id, "to", *update.To))
	}

	if update.Rule != nil {
		rule := uuid.Nil
		check(rule.UnmarshalText([]byte(*update.Rule)))
		check(updateRuleMail(h.db, id, rule))
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
}

func (h MailDB) GetDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := getDomains(h.db)
	if err != nil {
		log.Errorf("failed to get domains: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("unknown internal server error"))
		return
	}

	json, err := json.Marshal(domains)
	check(err)

	w.WriteHeader(http.StatusOK)
	w.Write(json)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
