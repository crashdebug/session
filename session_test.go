package session

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
)

func TestSession(t *testing.T) {
	st := NewMemoryStorage()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, err := Get(st, new(TestState), w, r, "sid")

		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			t.Fatal(err)
			return
		}

		session.EndRequest()
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	go func() { http.ListenAndServe(":8000", nil) }()

	cookies, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: cookies}
	u, err := url.Parse("http://localhost:8000")
	if err != nil {
		t.Fatal(err)
	}

	if r, err := client.Get(u.String()); err != nil {
		t.Fatal(err)
	} else if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	cookie := ""
	if i := len(cookies.Cookies(u)); i != 1 {
		t.Fatalf("Expected to get one cookie, got %d", i)
	} else {
		cookie = cookies.Cookies(u)[0].Value
	}

	if r, err := client.Get(u.String()); err != nil {
		t.Fatal(err)
	} else if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}

	if i := len(cookies.Cookies(u)); i != 1 {
		t.Fatalf("Expected to get one cookie, got %d", i)
	} else if cookie == cookies.Cookies(u)[0].Value {
		t.Fatal("Cookie value did not change between requests")
	} else if cookie[:32] != cookies.Cookies(u)[0].Value[:32] {
		t.Fatal("Session ID changed")
	}
}

type TestState struct {
	UserName string
}
