package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	rnd "math/rand"
	"net/http"
	"strings"
	"time"
)

// Storage is an interface which helps store sessions.
type Storage interface {
	GetSession(id string) (*Session, error)
	SetSession(*Session) error
}

// MemoryStorage is an in-memory Storage implementation for quick prototyping.
type MemoryStorage struct {
	sessions map[string]*Session
}

// State type provides session state information, such as session variables.
type State struct {
	nonce *big.Int
}

// Session type represents the current user session.
type Session struct {
	id         string
	Created    time.Time
	LastAccess time.Time
	Data       []byte
	state      *State
	finalize   func()
}

type stateData struct {
	Nonce *big.Int
}

// NewSession creates a new session.
func NewSession(id string) *Session {
	return &Session{
		id:         id,
		Created:    time.Now(),
		LastAccess: time.Now(),
	}
}

// ID returns the current session ID.
func (s *Session) ID() string {
	return s.id
}

// EndRequest should be called at the end of each request to finalize the session state.
func (s *Session) EndRequest() {
	if s.finalize != nil {
		s.finalize()
		s.finalize = nil
	}
}

func (s *Session) getState(key []byte) (*State, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := s.id[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	dst := make([]byte, len(s.Data))
	mode.CryptBlocks(dst, s.Data)

	var data stateData
	dec := json.NewDecoder(bytes.NewBuffer(dst))
	if err = dec.Decode(&data); err != nil {
		return nil, err
	}
	s.state = &State{nonce: data.Nonce}
	return s.state, nil
}

func (s *Session) setState(state *State, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := s.id[:aes.BlockSize]
	mode := cipher.NewCBCEncrypter(block, []byte(iv))

	d, err := json.Marshal(&stateData{Nonce: state.nonce})
	if err != nil {
		return err
	}
	if len(d)%aes.BlockSize != 0 {
		d = append(d, make([]byte, aes.BlockSize-(len(d)%aes.BlockSize))...)
	}
	s.Data = make([]byte, len(d))
	mode.CryptBlocks(s.Data, d)

	return nil
}

// Get returns a session based on the HTTP request.
func Get(st Storage, w http.ResponseWriter, r *http.Request, cookieName string) (*Session, error) {
	var sessionID string
	var symkey []byte
	var state *State
	alg := sha256.New()

	if cookie, err := r.Cookie(cookieName); err == nil {
		values := strings.Split(cookie.Value, ".")
		if len(values) == 3 {
			sessionID = values[0]
			if symkey, err = base64.StdEncoding.DecodeString(values[1]); err == nil {
				if hash, err := base64.StdEncoding.DecodeString(values[2]); err == nil {
					if session, err := st.GetSession(values[0]); err == nil {
						if state, err = session.getState(symkey); err == nil {
							alg.Write(state.nonce.Bytes())
							alg.Write([]byte(values[0]))
							alg.Write(symkey)
							if checkHash(alg.Sum(nil), hash) {
								session.finalize = func() {
									state.nonce = state.nonce.Add(state.nonce, big.NewInt(1))
									session.LastAccess = time.Now()

									alg.Reset()
									alg.Write(state.nonce.Bytes())
									alg.Write([]byte(values[0]))
									alg.Write(symkey)

									session.setState(state, symkey)
									st.SetSession(session)
									set(w, cookieName, sessionID, r.Host, symkey, alg.Sum(nil))
								}
								return session, nil
							}
							log.Println("Hash mismatch.")
						} else {
							log.Printf("Could not get authentication state. %s", err)
						}
					} else {
						log.Printf("Could not get session from storage. %s", err)
					}
				} else {
					log.Printf("Could not decode hash. %s", err)
				}
			} else {
				log.Printf("Could not decode symmetric key. %s", err)
			}
		} else {
			log.Printf("Invalid cookie value: %s", cookie.Value)
		}
	}

	if sessionID == "" {
		sessionID = randSeq(32)
	}

	session := NewSession(sessionID)
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	symkey = make([]byte, 32)
	if i, err := rand.Read(symkey); err != nil {
		return nil, err
	} else if i < len(symkey) {
		return nil, fmt.Errorf("Could not generate key")
	}
	state = &State{
		nonce: nonce,
	}
	session.setState(state, symkey)
	if err := st.SetSession(session); err != nil {
		return nil, err
	}

	alg.Write(state.nonce.Bytes())
	alg.Write([]byte(sessionID))
	alg.Write(symkey)

	set(w, cookieName, sessionID, r.Host, symkey, alg.Sum(nil))

	return session, nil
}

func set(w http.ResponseWriter, cookieName, sessionID, domain string, symkey, hash []byte) {
	w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s.%s.%s; Domain: %s; Path=/; HttpOnly", cookieName, sessionID, base64.StdEncoding.EncodeToString(symkey), base64.StdEncoding.EncodeToString(hash), domain))
}

// NewMemoryStorage creates a new in-memory storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{make(map[string]*Session)}
}

// GetSession returns a session with the specified id or an error if no session can be found.
func (st *MemoryStorage) GetSession(id string) (*Session, error) {
	if s, ok := st.sessions[id]; ok {
		return s, nil
	}
	return nil, fmt.Errorf("No session with ID '%s' could be found", id)
}

// SetSession stores a session into the storage.
func (st *MemoryStorage) SetSession(session *Session) error {
	st.sessions[session.ID()] = session
	return nil
}

func checkHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func init() {
	rnd.Seed(time.Now().UnixNano())
}

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rnd.Intn(len(letters))]
	}
	return string(b)
}
