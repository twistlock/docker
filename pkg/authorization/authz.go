package authorization

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

// NewCtx creates new authZ context, it is used to store authorization information related to a specific docker
// REST http session
// A context provides two method:
// Authenticate Request:
// Call authZ plugins with current REST request and AuthN response
// Request contains full HTTP packet sent to the docker daemon
// https://docs.docker.com/reference/api/docker_remote_api/
//
// Authenticate Response:
// Call authZ plugins with full info about current REST request, REST response and AuthN response
// The response from this method may contains content that overrides the daemon response
// This allows authZ plugins to filter privileged content
//
// If multiple authZ plugins are specified, the block/allow decision is based on ANDing all plugin results
// For response manipulation, the response from each plugin is piped between plugins. Plugin execution order
// is determined according to daemon parameters
func NewCtx(authZPlugins []AuthorizationPlugin, user, userAuthNMethod, requestMethod, requestUri string) *Ctx {
	return &Ctx{plugins: authZPlugins, user: user, userAuthNMethod: userAuthNMethod, requestMethod: requestMethod, requestUri: requestUri}
}

type Ctx struct {
	user            string
	userAuthNMethod string
	requestMethod   string
	requestUri      string
	plugins         []AuthorizationPlugin
	// authReq stores the cached request object for the current transaction
	authReq *Request
}

// AuthRequest authorized the request to the docker daemon using authZ plugins
func (a *Ctx) AuthZRequest(w http.ResponseWriter, r *http.Request) (err error) {

	if err != nil {
		return err
	}

	var drainedBody io.ReadCloser
	drainedBody, r.Body, err = drainBody(r.Body)
	if err != nil {
		return
	}

	body, err := ioutil.ReadAll(drainedBody)
	defer drainedBody.Close()

	if err != nil {
		return err
	}

	var headers bytes.Buffer
	err = r.Header.Write(&headers)

	if err != nil {
		return err
	}

	a.authReq = &Request{
		User:            a.user,
		UserAuthNMethod: a.userAuthNMethod,
		RequestMethod:   a.requestMethod,
		RequestUri:      a.requestUri,
		RequestBody:     body,
		RequestHeaders:  headers.Bytes()}

	for _, plugin := range a.plugins {

		authRes, err := plugin.AuthZRequest(a.authReq)

		if err != nil {
			return err
		}

		if !authRes.Allow {
			return fmt.Errorf(authRes.Msg)
		}
	}

	return nil
}

// AuthRequest authorized and manipulates the response from docker daemon using authZ plugins
func (a *Ctx) AuthZResponse(rm ResponseModifier, r *http.Request) error {

	modifiedBody := rm.RawBody()
	modifiedHeaders, err := rm.RawHeaders()

	if err != nil {
		return err
	}

	modifiedStatusCode := rm.StatusCode()

	for _, plugin := range a.plugins {

		a.authReq.ResponseBody = modifiedBody
		a.authReq.ResponseHeaders = modifiedHeaders
		a.authReq.ResponseStatusCode = modifiedStatusCode

		authRes, err := plugin.AuthZResponse(a.authReq)

		if err != nil {
			return err
		}

		if !authRes.Allow {
			return fmt.Errorf(authRes.Msg)
		}

		// Take latest response data from authZ plugin
		if authRes.ModifiedBody != nil {
			modifiedBody = authRes.ModifiedBody
		}

		if authRes.ModifiedHeader != nil {
			modifiedHeaders = authRes.ModifiedHeader
		}

		if authRes.ModifiedStatusCode > 0 {
			modifiedStatusCode = authRes.ModifiedStatusCode
		}
	}

	if modifiedBody != nil {
		rm.OverrideBody(modifiedBody)
	}
	if modifiedHeaders != nil {
		rm.OverrideHeader(modifiedHeaders)
	}

	rm.Flush()

	return nil
}

// drainBody dump the body, it reads the body data into memory and
// see go sources /go/src/net/http/httputil/dump.go
func drainBody(b io.ReadCloser) (r1, r2 io.ReadCloser, err error) {
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, nil, err
	}
	if err = b.Close(); err != nil {
		return nil, nil, err
	}
	return ioutil.NopCloser(&buf), ioutil.NopCloser(bytes.NewReader(buf.Bytes())), nil
}