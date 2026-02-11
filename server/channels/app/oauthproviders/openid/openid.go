// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package oauthopenid

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

type OpenIDProvider struct {
}

type OpenIDUser struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Nickname          string `json:"nickname"`
}

func init() {
	provider := &OpenIDProvider{}
	einterfaces.RegisterOAuthProvider(model.ServiceOpenid, provider)
}

func userFromOpenIDUser(logger mlog.LoggerIFace, oidcUser *OpenIDUser, settings *model.SSOSettings) *model.User {
	user := &model.User{}

	// Set username in order of preference
	var username string
	if settings != nil && model.SafeDereference(settings.UsePreferredUsername) && oidcUser.PreferredUsername != "" {
		// Split by @ and take the first part to maintain consistency with other providers
		username = strings.Split(oidcUser.PreferredUsername, "@")[0]
	} else if oidcUser.Nickname != "" {
		username = oidcUser.Nickname
	} else if oidcUser.PreferredUsername != "" {
		username = strings.Split(oidcUser.PreferredUsername, "@")[0]
	} else {
		// Fallback to email username
		username = strings.Split(oidcUser.Email, "@")[0]
	}
	user.Username = model.CleanUsername(logger, username)

	// Set first and last name
	if oidcUser.GivenName != "" {
		user.FirstName = oidcUser.GivenName
	}
	if oidcUser.FamilyName != "" {
		user.LastName = oidcUser.FamilyName
	}

	// Fallback to splitting the full name if first/last names are not provided
	if user.FirstName == "" && user.LastName == "" && oidcUser.Name != "" {
		splitName := strings.Split(oidcUser.Name, " ")
		if len(splitName) == 2 {
			user.FirstName = splitName[0]
			user.LastName = splitName[1]
		} else if len(splitName) >= 2 {
			user.FirstName = splitName[0]
			user.LastName = strings.Join(splitName[1:], " ")
		} else {
			user.FirstName = oidcUser.Name
		}
	}

	user.Email = strings.ToLower(oidcUser.Email)
	userId := oidcUser.getAuthData()
	user.AuthData = &userId
	user.AuthService = model.ServiceOpenid

	return user
}

func openIDUserFromJSON(data io.Reader) (*OpenIDUser, error) {
	decoder := json.NewDecoder(data)
	var oidcUser OpenIDUser
	err := decoder.Decode(&oidcUser)
	if err != nil {
		return nil, err
	}
	return &oidcUser, nil
}

func (oidcUser *OpenIDUser) IsValid() error {
	if oidcUser.Sub == "" {
		return errors.New("user sub (subject) cannot be empty")
	}

	if oidcUser.Email == "" {
		return errors.New("user email should not be empty")
	}

	return nil
}

func (oidcUser *OpenIDUser) getAuthData() string {
	return oidcUser.Sub
}

func (op *OpenIDProvider) GetUserFromJSON(rctx request.CTX, data io.Reader, tokenUser *model.User, settings *model.SSOSettings) (*model.User, error) {
	oidcUser, err := openIDUserFromJSON(data)
	if err != nil {
		return nil, err
	}
	if err = oidcUser.IsValid(); err != nil {
		return nil, err
	}

	return userFromOpenIDUser(rctx.Logger(), oidcUser, settings), nil
}

func (op *OpenIDProvider) GetSSOSettings(_ request.CTX, config *model.Config, service string) (*model.SSOSettings, error) {
	return &config.OpenIdSettings, nil
}

func (op *OpenIDProvider) GetUserFromIdToken(_ request.CTX, idToken string) (*model.User, error) {
	// For standard OAuth flow, this returns nil
	// ID token processing can be implemented if needed for specific flows
	return nil, nil
}

func (op *OpenIDProvider) IsSameUser(_ request.CTX, dbUser, oauthUser *model.User) bool {
	return dbUser.AuthData == oauthUser.AuthData
}
