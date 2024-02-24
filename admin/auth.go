package main

import (
	"context"
	"log"
	"net/http"

	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/settings"
)

const (
	adminLevel string = "admin"
	userLevel  string = "user"
	queryLevel string = "query"
	carveLevel string = "carve"
)

// Using the default name for the cookie in SAML:
// https://github.com/crewjam/saml/blob/main/samlsp/session_cookie.go#L11
const (
	authCookieName = "token"
)

// Handler to check access to a resource based on the authentication enabled
func handlerAuthCheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch adminConfig.Auth {
		case settings.AuthDB:
			// Check if user is already authenticated
			authenticated, session := sessionsmgr.CheckAuth(r, sessions.SessionTypeDB)
			if !authenticated {
				http.Redirect(w, r, loginPath, http.StatusFound)
				return
			}
			// Set middleware values
			s := make(sessions.ContextValue)
			s[sessions.CtxUser] = session.Username
			s[sessions.CtxCSRF] = session.Values[sessions.CtxCSRF].(string)
			ctx := context.WithValue(r.Context(), sessions.ContextKey(sessions.CtxSession), s)
			// Update metadata for the user
			if err := adminUsers.UpdateMetadata(session.IPAddress, session.UserAgent, session.Username, s[sessions.CtxCSRF]); err != nil {
				log.Printf("error updating metadata for user %s: %v", session.Username, err)
			}
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		case settings.AuthSAML:
			_, err := samlMiddleware.Session.GetSession(r)
			if err != nil {
				log.Printf("GetSession %v", err)
				http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
				return
			}
			var jwtdata JWTData
			var activeCookie *http.Cookie
			for _, c := range r.Cookies() {
				jwtdata, err = parseJWTFromCookie(samlData.KeyPair, c.Value)
				if err == nil {
					activeCookie = c
					break
				}
			}
			if jwtdata.Username == "" {
				http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
				return
			}
			// Check if user is already authenticated
			activeSession, err := sessionsmgr.Get(activeCookie.Value, sessions.SessionTypeSAML)
			if err != nil {
				http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
				return
			}
			// Check if active session matches with the JWT
			if activeSession.Username != jwtdata.Username {
				http.Redirect(w, r, forbiddenPath, http.StatusFound)
				return
			}
			// Check if user exists
			if !adminUsers.Exists(jwtdata.Username) {
				log.Printf("user not found: %s", jwtdata.Username)
				http.Redirect(w, r, forbiddenPath, http.StatusFound)
				return
			}
			// Set middleware values
			s := make(sessions.ContextValue)
			s[sessions.CtxUser] = activeSession.Username
			s[sessions.CtxCSRF] = activeSession.Values[sessions.CtxCSRF].(string)
			ctx := context.WithValue(r.Context(), sessions.ContextKey(sessions.CtxSession), s)
			// Update metadata for the user
			err = adminUsers.UpdateMetadata(activeSession.IPAddress, activeSession.UserAgent, activeSession.Username, s[sessions.CtxCSRF])
			if err != nil {
				log.Printf("error updating metadata for user %s: %v", activeSession.Username, err)
			}
			log.Printf("CSRF for user %s is %s", activeSession.Username, s[sessions.CtxCSRF])
			// Access granted
			samlMiddleware.RequireAccount(h).ServeHTTP(w, r.WithContext(ctx))
		}
	})
}
