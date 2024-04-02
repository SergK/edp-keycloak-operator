package adapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v12"
	"github.com/go-logr/logr"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"

	"github.com/epam/edp-keycloak-operator/pkg/client/keycloak/api"
	"github.com/epam/edp-keycloak-operator/pkg/client/keycloak/dto"
)

const (
	idPResource                     = "/admin/realms/{realm}/identity-provider/instances"
	idPMapperResource               = "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers"
	getOneIdP                       = idPResource + "/{alias}"
	openIdConfig                    = "/realms/{realm}/.well-known/openid-configuration"
	authExecutions                  = "/admin/realms/{realm}/authentication/flows/browser/executions"
	authExecutionConfig             = "/admin/realms/{realm}/authentication/executions/{id}/config"
	postClientScopeMapper           = "/admin/realms/{realm}/client-scopes/{scopeId}/protocol-mappers/models"
	getRealmClientScopes            = "/admin/realms/{realm}/client-scopes"
	postClientScope                 = "/admin/realms/{realm}/client-scopes"
	putClientScope                  = "/admin/realms/{realm}/client-scopes/{id}"
	getClientProtocolMappers        = "/admin/realms/{realm}/clients/{id}/protocol-mappers/models"
	mapperToIdentityProvider        = "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers"
	updateMapperToIdentityProvider  = "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{id}"
	authFlows                       = "/admin/realms/{realm}/authentication/flows"
	authFlow                        = "/admin/realms/{realm}/authentication/flows/{id}"
	authFlowExecutionCreate         = "/admin/realms/{realm}/authentication/executions"
	authFlowExecutionGetUpdate      = "/admin/realms/{realm}/authentication/flows/{alias}/executions"
	authFlowExecutionDelete         = "/admin/realms/{realm}/authentication/executions/{id}"
	raiseExecutionPriority          = "/admin/realms/{realm}/authentication/executions/{id}/raise-priority"
	lowerExecutionPriority          = "/admin/realms/{realm}/authentication/executions/{id}/lower-priority"
	authFlowExecutionConfig         = "/admin/realms/{realm}/authentication/executions/{id}/config"
	authFlowConfig                  = "/admin/realms/{realm}/authentication/config/{id}"
	deleteClientScopeProtocolMapper = "/admin/realms/{realm}/client-scopes/{clientScopeID}/protocol-mappers/models/{protocolMapperID}"
	createClientScopeProtocolMapper = "/admin/realms/{realm}/client-scopes/{clientScopeID}/protocol-mappers/models"
	putDefaultClientScope           = "/admin/realms/{realm}/default-default-client-scopes/{clientScopeID}"
	deleteDefaultClientScope        = "/admin/realms/{realm}/default-default-client-scopes/{clientScopeID}"
	getDefaultClientScopes          = "/admin/realms/{realm}/default-default-client-scopes"
	realmEventConfigPut             = "/admin/realms/{realm}/events/config"
	realmComponent                  = "/admin/realms/{realm}/components"
	realmComponentEntity            = "/admin/realms/{realm}/components/{id}"
	identityProviderEntity          = "/admin/realms/{realm}/identity-provider/instances/{alias}"
	identityProviderCreateList      = "/admin/realms/{realm}/identity-provider/instances"
	idpMapperCreateList             = "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers"
	idpMapperEntity                 = "/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{id}"
	deleteRealmUser                 = "/admin/realms/{realm}/users/{id}"
	setRealmUserPassword            = "/admin/realms/{realm}/users/{id}/reset-password"
	getUserRealmRoleMappings        = "/admin/realms/{realm}/users/{id}/role-mappings/realm"
	getUserGroupMappings            = "/admin/realms/{realm}/users/{id}/groups"
	manageUserGroups                = "/admin/realms/{realm}/users/{userID}/groups/{groupID}"
	logClientDTO                    = "client dto"
)

const (
	keycloakApiParamId            = "id"
	keycloakApiParamRole          = "role"
	keycloakApiParamRealm         = "realm"
	keycloakApiParamAlias         = "alias"
	keycloakApiParamClientScopeId = "clientScopeID"
)

const (
	logKeyUser  = "user dto"
	logKeyRealm = "realm"
)

type TokenExpiredError string

func (e TokenExpiredError) Error() string {
	return string(e)
}

func IsErrTokenExpired(err error) bool {
	errTokenExpired := TokenExpiredError("")

	return errors.As(err, &errTokenExpired)
}

type GoCloakAdapter struct {
	client     GoCloak
	token      *gocloak.JWT
	log        logr.Logger
	basePath   string
	legacyMode bool
}

type JWTPayload struct {
	Exp int64 `json:"exp"`
}

func (a GoCloakAdapter) GetGoCloak() GoCloak {
	return a.client
}

func MakeFromToken(url string, tokenData []byte, log logr.Logger, caCertificatePath string) (*GoCloakAdapter, error) {
	var token gocloak.JWT
	if err := json.Unmarshal(tokenData, &token); err != nil {
		return nil, errors.Wrapf(err, "unable decode json data")
	}

	const requiredTokenParts = 3

	tokenParts := strings.Split(token.AccessToken, ".")

	if len(tokenParts) < requiredTokenParts {
		return nil, errors.New("wrong JWT token structure")
	}

	tokenPayload, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, errors.Wrap(err, "wrong JWT token base64 encoding")
	}

	var tokenPayloadDecoded JWTPayload
	if err = json.Unmarshal(tokenPayload, &tokenPayloadDecoded); err != nil {
		return nil, errors.Wrap(err, "unable to decode JWT payload json")
	}

	if tokenPayloadDecoded.Exp < time.Now().Unix() {
		return nil, TokenExpiredError("token is expired")
	}

	kcCl, legacyMode, err := makeClientFromToken(url, token.AccessToken, caCertificatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to make new keycloak client: %w", err)
	}

	return &GoCloakAdapter{
		client:     kcCl,
		token:      &token,
		log:        log,
		basePath:   url,
		legacyMode: legacyMode,
	}, nil
}

// makeClientFromToken returns Keycloak client, a bool flag indicating whether it was created in legacy mode and an error.
func makeClientFromToken(url, token string, caCertificatePath string) (*gocloak.GoCloak, bool, error) {
	restyClient := resty.New()

	if caCertificatePath != "" {
		caCert, err := ioutil.ReadFile(caCertificatePath)
		if err != nil {
			return nil, false, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		restyClient.SetTLSClientConfig(&tls.Config{
			RootCAs: caCertPool,
		})
	}

	kcCl := gocloak.NewClient(url)
	kcCl.SetRestyClient(restyClient)

	_, err := kcCl.GetRealms(context.Background(), token)
	if err == nil {
		return kcCl, false, nil
	}

	if isNotLegacyResponseCode(err) {
		return nil, false, fmt.Errorf("unexpected error received while trying to get realms using the modern client: %w", err)
	}

	kcCl = gocloak.NewClient(url, gocloak.SetLegacyWildFlySupport())
	kcCl.SetRestyClient(restyClient)

	if _, err := kcCl.GetRealms(context.Background(), token); err != nil {
		return nil, false, fmt.Errorf("failed to create both current and legacy clients: %w", err)
	}

	return kcCl, true, nil
}

func MakeFromServiceAccount(ctx context.Context,
	url, clientID, clientSecret, realm string,
	log logr.Logger, restyClient *resty.Client, caCertificatePath string,
) (*GoCloakAdapter, error) {
	if restyClient == nil {
		restyClient = resty.New()
	}

	if caCertificatePath != "" {
		caCert, err := ioutil.ReadFile(caCertificatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		restyClient.SetTLSClientConfig(&tls.Config{
			RootCAs: caCertPool,
		})
	}

	kcCl := gocloak.NewClient(url)
	kcCl.SetRestyClient(restyClient)

	token, err := kcCl.LoginClient(ctx, clientID, clientSecret, realm)
	if err == nil {
		return &GoCloakAdapter{
			client:     kcCl,
			token:      token,
			log:        log,
			basePath:   url,
			legacyMode: false,
		}, nil
	}

	if isNotLegacyResponseCode(err) {
		return nil, fmt.Errorf("unexpected error received while trying to get realms using the modern client: %w", err)
	}

	kcCl = gocloak.NewClient(url, gocloak.SetLegacyWildFlySupport())
	kcCl.SetRestyClient(restyClient)

	token, err = kcCl.LoginClient(ctx, clientID, clientSecret, realm)
	if err != nil {
		return nil, fmt.Errorf("failed to login with client creds on both current and legacy clients - "+
			"clientID: %s, realm: %s: %w", clientID, realm, err)
	}

	return &GoCloakAdapter{
		client:     kcCl,
		token:      token,
		log:        log,
		basePath:   url,
		legacyMode: true,
	}, nil
}

func isNotLegacyResponseCode(err error) bool {
	apiErr := new(gocloak.APIError)
	ok := errors.As(err, &apiErr)

	return !ok || (apiErr.Code != http.StatusNotFound && apiErr.Code != http.StatusServiceUnavailable)
}

func Make(ctx context.Context, url, user, password string, log logr.Logger, restyClient *resty.Client, caCertificatePath string) (*GoCloakAdapter, error) {
	if restyClient == nil {
		restyClient = resty.New()
	}

	if caCertificatePath != "" {
		caCert, err := ioutil.ReadFile(caCertificatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		restyClient.SetTLSClientConfig(&tls.Config{
			RootCAs: caCertPool,
		})
	}

	kcCl := gocloak.NewClient(url)
	kcCl.SetRestyClient(restyClient)

	token, err := kcCl.LoginAdmin(ctx, user, password, "master")
	if err == nil {
		return &GoCloakAdapter{
			client:     kcCl,
			token:      token,
			log:        log,
			basePath:   url,
			legacyMode: false,
		}, nil
	}

	if isNotLegacyResponseCode(err) {
		return nil, fmt.Errorf("unexpected error received while trying to get realms using the modern client: %w", err)
	}

	kcCl = gocloak.NewClient(url, gocloak.SetLegacyWildFlySupport())
	kcCl.SetRestyClient(restyClient)

	token, err = kcCl.LoginAdmin(ctx, user, password, "master")
	if err != nil {
		return nil, errors.Wrapf(err, "cannot login to keycloak server with user: %s", user)
	}

	return &GoCloakAdapter{
		client:     kcCl,
		token:      token,
		log:        log,
		basePath:   url,
		legacyMode: true,
	}, nil
}

func (a GoCloakAdapter) ExportToken() ([]byte, error) {
	tokenData, err := json.Marshal(a.token)
	if err != nil {
		return nil, errors.Wrap(err, "unable to json encode token")
	}

	return tokenData, nil
}

// buildPath returns request path corresponding with the mode the client is operating in.
func (a GoCloakAdapter) buildPath(endpoint string) string {
	if a.legacyMode {
		return a.basePath + "/auth" + endpoint
	}

	return a.basePath + endpoint
}

// Other unmodified methods remain the same.