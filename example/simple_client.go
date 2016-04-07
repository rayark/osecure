package main

import (
	"fmt"
	"github.com/julienschmidt/httprouter"
	"github.com/rayark/osecure"
	"github.com/rayark/zin"
	"github.com/rayark/zin/middleware"
	"log"
	"net/http"
)

type App struct {
	osecure *osecure.OAuthSession
}

func (app *App) Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprint(w, "Index\n")
}

func (app *App) LoggedIn(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprint(w, "Logged in\n")
}

func (app *App) LogOut(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprint(w, "Logged out\n")
}

func (app *App) Meowmeow(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if app.osecure.HasPermission(w, r, "cat") {
		fmt.Fprint(w, "Meowmeow =OwO=\n")
	} else {
		fmt.Fprint(w, "No meow for you\n")
	}
}

func (app *App) GetServerToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	reply, err := app.osecure.GetServerToken("57063c3bf32193000195a9f4.sentry.rayark.com")

	if err != nil {
		panic(err)
	}

	targetOsecure := osecure.NewOAuthSession("simple_client",
		&osecure.OAuthConfig{
			ClientID:                 "57063c3bf32193000195a9f4.sentry.rayark.com",
			Secret:                   "tfdkocA0XSUe4KxqqHPRUXtD-EkWMbyqYghkpkaHme4CvAY0M9NsUUdEsBLwY2Ny",
			AuthURL:                  "http://localhost:8000/authorize",
			TokenURL:                 "http://localhost:8000/token",
			PermissionsURL:           "http://localhost:8000/permissions",
			ServerTokenURL:           "http://localhost:8000/get_server_token",
			ServerTokenEncryptionKey: "e8635134ceb0422ee2b52753cc1bdda15e9aec9e880c5d1eabd3be74f0dce685",
		},
		nil,
		"http://localhost:8080/auth",
	)

	token, err := targetOsecure.DecryptServerToken(reply.ServerToken, "57063c36f32193000195a9f3.sentry.rayark.com")
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, token)
}

func main() {
	app := &App{
		osecure: osecure.NewOAuthSession("simple_client",
			&osecure.OAuthConfig{
				ClientID:                 "57063c36f32193000195a9f3.sentry.rayark.com",
				Secret:                   "nEmLGx5gXgn2-30HZ0GRTjct1GE2jOKnK7V_yaijUPpKCiEiUPbxqkL0i0-zEpm-",
				AuthURL:                  "http://localhost:8000/authorize",
				TokenURL:                 "http://localhost:8000/token",
				PermissionsURL:           "http://localhost:8000/permissions",
				ServerTokenURL:           "http://localhost:8000/get_server_token",
				ServerTokenEncryptionKey: "4601fc97ffcfbe921b765c95754c82b919721305d3cf4a41dcf6d1e8b86e5f2d",
			},
			nil,
			"http://localhost:8080/auth",
		),
	}
	router := httprouter.New()

	def := zin.NewGroup("/", middleware.Logger)
	def.R(router.GET, "", app.Index)
	def.R(router.GET, "login", zin.WrapS(app.osecure.Secured)(app.LoggedIn))
	def.R(router.GET, "meowmeow", zin.WrapS(app.osecure.Secured)(app.Meowmeow))
	def.R(router.GET, "logout", zin.WrapH(app.osecure.ExpireSession("/")))
	def.R(router.GET, "get_server_token", app.GetServerToken)
	def.R(router.GET, "auth", zin.WrapF(app.osecure.CallbackView))

	log.Print("// Server started at port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
