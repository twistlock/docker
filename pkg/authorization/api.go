package authorization

const (
// POST method for daemon request authorization
	AuthZApiRequest = "AuthZPlugin.AuthZReq"

// POST method for daemon response authorization
	AuthZApiResponse = "AuthZPlugin.AuthZRes"

// Name of the interface all AuthZ plugins implement
	AuthZApiImplements = "authz"
)

// Request holds data required for authZ plugins
type Request struct {
	// User holds the user extracted by AuthN mechanism
	User string `json:"User,omitempty"`

	// UserAuthNMethod holds the mechanism used to extract user details (e.g., krb)
	UserAuthNMethod string `json:"UserAuthNMethod,omitempty"`

	// RequestMethod holds the HTTP method (GET/POST/PUT)
	RequestMethod string `json:"RequestMethod,omitempty"`

	// RequestUri holds the full HTTP uri (e.g., /v1.21/version)
	RequestUri string `json:"RequestUri,omitempty"`

	// RequestBody stores the raw request body sent to the docker daemon
	RequestBody []byte `json:"RawRequestBody,omitempty"`

	// RequestHeaders stores the raw request headers sent to the docker daemon
	RequestHeaders []byte `json:"RawRequestHeaders,omitempty"`

	// ResponseStatusCode stores the status code returned from docker daemon
	ResponseStatusCode int `json:"ResponseStatusCode,omitempty"`

	// ResponseBody stores the raw response body sent from docker daemon
	ResponseBody []byte `json:"RawResponseBody,omitempty"`

	// ResponseHeaders stores the raw response headers sent to the docker daemon
	ResponseHeaders []byte `json:"RawResponseHeaders,omitempty"`
}

// Request is the expect object that returns from the authZ plugin
type Response struct {

	// Allow indicating whether the user is allowed or not
	Allow bool `json:"Allow"`

	// Msg stores the authorization message
	Msg string `json:"Msg,omitempty"`

	// ModifiedResponse stores the modified body of the response
	ModifiedBody []byte `json:"ModifiedBody,omitempty"`

	// ModifiedHeader stores the modified header of the response
	ModifiedHeader []byte `json:"ModifiedHeader,omitempty"`

	// ModifiedStatusCode is the modified status code of the response
	ModifiedStatusCode int `json:"ModifiedStatusCode,omitempty"`
}