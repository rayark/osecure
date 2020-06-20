package main

import (
	"fmt"
	"github.com/julienschmidt/httprouter"
	"github.com/rayark/osecure/v3"
	osecure_contrib "github.com/rayark/osecure/v3/contrib"
	"github.com/rayark/osecure/v3/inter_server"
	"github.com/rayark/zin"
	"github.com/rayark/zin/middleware"
	"log"
	"net/http"
)

type App struct {
	osecure     *osecure.OAuthSession
	interServer *inter_server.InterServer
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
	sessionData, ok := osecure.GetRequestSessionData(r)
	if ok && sessionData.HasPermission("cat") {
		fmt.Fprint(w, "Meowmeow =OwO=\n")
	} else {
		fmt.Fprint(w, "No meow for you\n")
	}
}

func (app *App) GetServerToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	reply, err := app.interServer.GetServerToken("57063c3bf32193000195a9f4.sentry.rayark.com")
	if err != nil {
		panic(err)
	}

	targetInterServer := inter_server.NewInterServer(
		&inter_server.InterServerConfig{
			InterServerClientID:      "57063c3bf32193000195a9f4.sentry.rayark.com",
			ServerTokenURL:           "http://localhost:8000/get_server_token",
			ServerTokenEncryptionKey: "e8635134ceb0422ee2b52753cc1bdda15e9aec9e880c5d1eabd3be74f0dce685",
		},
	)

	token, err := targetInterServer.DecryptServerToken(reply.ServerToken, "57063c36f32193000195a9f3.sentry.rayark.com")
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, token)
}

func main() {
	app := &App{
		osecure: osecure.NewOAuthSession("simple_client",
			&osecure.CookieConfig{
				SigningKey:    "44G/44KJ44GP44KL44G+44G744KK44KT44GP44KL44KK44KT44GxIO+8iOKXj+KAsuKIgOKAte+8ieODjuKZoQ==",
				EncryptionKey: "44GP44KL44KK44KT44Gx44CcICDlkpXlmpXpnYjms6I=",
			},
			&osecure.OAuthConfig{
				ClientID:     "57063c36f32193000195a9f3.sentry.rayark.com",
				ClientSecret: "nEmLGx5gXgn2-30HZ0GRTjct1GE2jOKnK7V_yaijUPpKCiEiUPbxqkL0i0-zEpm-",
				Scopes:       []string{"openid", "profile", "email"},
				AuthURL:      "http://localhost:8000/auth",
				TokenURL:     "http://localhost:8000/token",
				AppIDList:    []string{},
			},
			//&osecure.TokenVerifier{IntrospectTokenFunc: osecure_contrib.GoogleIntrospection(), GetPermissionsFunc: osecure_contrib.CommonPermissionRoles([]string{"user", "cat"})},
			&osecure.TokenVerifier{IntrospectTokenFunc: osecure_contrib.GoogleIntrospection(), GetPermissionsFunc: osecure_contrib.PredefinedPermissionRoles(map[string][]string{"123456789012345678901": {"user", "cat"}})},
			"http://localhost:8080/auth",
			&osecure.StateHandler{
				StateGenerator: osecure.DefaultStateGenerator,
				StateVerifier:  osecure.DefaultStateVerifier,
			},
		),
		interServer: inter_server.NewInterServer(
			&inter_server.InterServerConfig{
				InterServerClientID:      "57063c36f32193000195a9f3.sentry.rayark.com",
				ServerTokenURL:           "http://localhost:8000/get_server_token",
				ServerTokenEncryptionKey: "4601fc97ffcfbe921b765c95754c82b919721305d3cf4a41dcf6d1e8b86e5f2d",
			},
		),
	}

	router := httprouter.New()

	def := zin.NewGroup("/", middleware.Logger)
	def.R(router.GET, "", app.Index)
	def.R(router.GET, "login", zin.WrapS(app.osecure.SecuredH(false))(app.LoggedIn))
	def.R(router.GET, "meowmeow", zin.WrapS(app.osecure.SecuredH(true))(app.Meowmeow))
	def.R(router.GET, "logout", zin.WrapH(app.osecure.ExpireSession("/")))
	def.R(router.GET, "get_server_token", app.GetServerToken)
	def.R(router.GET, "auth", zin.WrapF(app.osecure.CallbackView))

	log.Print("// Server started at port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
