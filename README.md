# Secure Session
Golang implementation of secure session handling over HTTP/S.

### Example
```go
st := session.NewMemoryStorage()
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	state := new(authState)
	session, err := session.Get(st, state, w, r, "SessionID")

	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}

	session.EndRequest()
	http.ServeFile(w, r, "index.htm")
})
```

This will be stored encrypted in the session storage
```go
type authState struct {
	UserName string
	Claims   []string
}
```
