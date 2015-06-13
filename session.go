package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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

// Session type represents the current user session.
type Session struct {
	id         string
	nonce      *big.Int
	Created    time.Time
	LastAccess time.Time
	Data       []byte
	finalize   func()
}

type stateData struct {
	Nonce *big.Int
	Data  []byte
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

func (s *Session) getState(state interface{}, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv := s.id[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	dst := make([]byte, len(s.Data))
	mode.CryptBlocks(dst, s.Data)

	buf := bytes.NewBuffer(dst)

	l, err := binary.ReadVarint(buf)
	if err != nil {
		return err
	}
	nonce := make([]byte, l)
	if _, err = buf.Read(nonce); err != nil {
		return err
	}

	var data stateData
	dec := json.NewDecoder(buf)
	if err = dec.Decode(&data); err != nil {
		return fmt.Errorf("JSON decode error: %s", err)
	}
	if err = json.Unmarshal(data.Data, state); err != nil {
		return err
	}
	s.nonce = data.Nonce
	log.Printf("%+v", state)
	return nil
}

func (s *Session) setState(state interface{}, key []byte) error {
	if state == nil {
		return fmt.Errorf("State cannot be nil")
	}
	if key == nil || len(key) == 0 {
		return fmt.Errorf("Invalid key (%v)", key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := s.id[:aes.BlockSize]
	mode := cipher.NewCBCEncrypter(block, []byte(iv))

	buf := new(bytes.Buffer)
	nonce := s.nonce.Bytes()
	writeVarint(len(nonce), buf)
	buf.Write(nonce)

	d, err := json.Marshal(state)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(buf)
	err = enc.Encode(&stateData{Nonce: s.nonce, Data: d})
	if err != nil {
		return err
	}
	d = buf.Bytes()
	if len(d)%aes.BlockSize != 0 {
		d = append(d, make([]byte, aes.BlockSize-(len(d)%aes.BlockSize))...)
	}
	s.Data = make([]byte, len(d))
	mode.CryptBlocks(s.Data, d)

	return nil
}

// Get returns a session based on the HTTP request.
func Get(st Storage, state interface{}, w http.ResponseWriter, r *http.Request, cookieName string) (*Session, error) {
	var sessionID string
	var symkey []byte
	alg := sha256.New()

	if cookie, err := r.Cookie(cookieName); err == nil {
		values := strings.Split(cookie.Value, ".")
		if len(values) == 3 {
			sessionID = values[0]
			if symkey, err = base64.StdEncoding.DecodeString(values[1]); err == nil {
				if hash, err := base64.StdEncoding.DecodeString(values[2]); err == nil {
					if session, err := st.GetSession(values[0]); err == nil {
						if err = session.getState(state, symkey); err == nil {
							alg.Write(session.nonce.Bytes())
							alg.Write([]byte(values[0]))
							alg.Write(symkey)
							if checkHash(alg.Sum(nil), hash) {
								session.finalize = func() {
									session.nonce = session.nonce.Add(session.nonce, big.NewInt(1))
									session.LastAccess = time.Now()

									alg.Reset()
									alg.Write(session.nonce.Bytes())
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
							log.Printf("Could not get authentication state: %s", err)
						}
					} else {
						log.Printf("Could not get session from storage: %s", err)
					}
				} else {
					log.Printf("Could not decode hash: %s", err)
				}
			} else {
				log.Printf("Could not decode symmetric key: %s", err)
			}
		} else {
			log.Printf("Invalid cookie value: %s", cookie.Value)
		}
	} else {
		log.Printf("No cookie with name '%s'", cookieName)
	}

	if sessionID == "" {
		sessionID = randSeq(32)
	}

	session := NewSession(sessionID)
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	// state.SetNonce(nonce)
	session.nonce = nonce

	symkey = make([]byte, 32)
	if i, err := rand.Read(symkey); err != nil {
		return nil, err
	} else if i < len(symkey) {
		return nil, fmt.Errorf("Could not generate key")
	}
	session.setState(state, symkey)
	if err := st.SetSession(session); err != nil {
		return nil, err
	}

	alg.Write(session.nonce.Bytes())
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

func writeVarint(i int, buf *bytes.Buffer) {
	d := make([]byte, 8)
	buf.Write(d[:binary.PutVarint(d, int64(i))])
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
