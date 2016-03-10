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

func main() {
	app := &App{
		osecure: osecure.NewOAuthSession("simple_client",
			&osecure.OAuthConfig{
				ClientID:       "56de6ccb5eead200013fcbaf.sentry.rayark.com",
				Secret:         "rCP6jF_AWqXkYvvjVpHYpHnyms21D30DqQzVjqoRg9c24VcPmXRN6vk6Mt5KKYwN",
				AuthURL:        "http://localhost:8000/authorize",
				TokenURL:       "http://localhost:8000/token",
				PermissionsURL: "http://localhost:8000/permissions",
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
	def.R(router.GET, "auth", zin.WrapF(app.osecure.CallbackView))

	log.Print("// Server started at port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
