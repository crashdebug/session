# Secure Session
Golang implementation of secure session handling over HTTP/S.

### Example
```go
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
