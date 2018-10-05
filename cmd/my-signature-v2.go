package cmd

import (
	"strings"
	"fmt"
	"net/http"
	"sort"
	//"net/url"
)

func calculateV2(method string, encodedResource string, encodedQuery string, headers http.Header) string {
	cred := globalServerConfig.GetCredential()
	stringToSign := settingStringToSignV2(method, encodedResource, encodedQuery, headers, "")
	signature := calculateSignatureV2(stringToSign, cred.SecretKey)
	return signature
}

func reqAmzHeadersV2(headers http.Header) string {
	var keys []string
	keyval := make(map[string]string)
	for key := range headers {
		lkey := strings.ToLower(key)
		if !strings.HasPrefix(lkey, "x-amz-") {
			continue
		}
		keys = append(keys, lkey)
		keyval[lkey] = strings.Join(headers[key], ",")
	}
	sort.Strings(keys)
	var canonicalHeaders []string
	for _, key := range keys {
		canonicalHeaders = append(canonicalHeaders, key+":"+keyval[key])
	}
	return strings.Join(canonicalHeaders, "\n")
}

func reqResourceV2(encodedResource, encodedQuery string) string {
	queries := strings.Split(encodedQuery, "&")
	keyval := make(map[string]string)
	for _, query := range queries {
		key := query
		val := ""
		index := strings.Index(query, "=")
		if index != -1 {
			key = query[:index]
			val = query[index+1:]
		}
		keyval[key] = val
	}

	var reqQueries []string
	for _, key := range resourceList {
		val, ok := keyval[key]
		if !ok {
			continue
		}
		if val == "" {
			reqQueries = append(reqQueries, key)
			continue
		}
		reqQueries = append(reqQueries, key+"="+val)
	}

	// The queries will be already sorted as resourceList is sorted, if canonicalQueries
	// is empty strings.Join returns empty.
	reqQuery := strings.Join(reqQueries, "&")
	if reqQuery != "" {
		return encodedResource + "?" + reqQuery
	}
	return encodedResource
}

func settingStringToSignV2(method string, encodedResource, encodedQuery string, headers http.Header, expires string) string {
	reqHeaders := reqAmzHeadersV2(headers)

	if len(reqHeaders) > 0 {
		reqHeaders += "\n"
	}

	date := expires
	if date == "" {
		date = headers.Get("Date")
	}
	stringToSign := strings.Join([]string{
		method,
		headers.Get("Content-MD5"),
		headers.Get("Content-Type"),
		date,
		reqHeaders,
	}, "\n")

	return stringToSign + reqResourceV2(encodedResource, encodedQuery)
}


func formattingRequest(r *http.Request) (*http.Request, APIErrorCode){
	v2Auth := r.Header.Get("Authorization")

	if v2Auth == "" {
		return r,ErrAuthHeaderEmpty
	}
	if !strings.HasPrefix(v2Auth, signV2Algorithm) {
		return r,ErrSignatureVersionNotSupported
	}

	authFields := strings.Split(v2Auth, " ")
	if len(authFields) != 2 {
		return r,ErrMissingFields
	}

	keySignFields := strings.Split(strings.TrimSpace(authFields[1]), ":")
	if len(keySignFields) != 2 {
		return r,ErrMissingFields
	}
	cred := globalServerConfig.GetCredential()
	if keySignFields[0] != cred.AccessKey {
		keySignFields[0] = cred.AccessKey
	}

	tokens := strings.SplitN(r.RequestURI, "?", 2)
	encodedResource := tokens[0]
	encodedQuery := ""
	if len(tokens) == 2 {
		encodedQuery = tokens[1]
	}

	unescapedQueries, err := unescapeQueries(encodedQuery)
	if err != nil {
		return r,ErrInvalidQueryParams
	}
	encodedResource, err = getResource(encodedResource, r.Host, globalDomainName)
	if err != nil {
		return r,ErrInvalidRequest
	}

	prefix := fmt.Sprintf("%s %s:", signV2Algorithm, keySignFields[0])
	fmt.Println(prefix)

	v2Auth = v2Auth[len(prefix):]
	expectedAuth := calculateV2(r.Method, encodedResource, strings.Join(unescapedQueries, "&"), r.Header)
	fmt.Println(expectedAuth)
	r.Header.Set("Authorization",prefix+expectedAuth)
	fmt.Println(globalServerConfig.GetCredential())
	return r,ErrNone
}

func printRequest(r *http.Request) string{
	var request []string
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, url)
	request = append(request, fmt.Sprintf("Host: %v", r.Host))
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		r.ParseForm()
		request = append(request, "\n")
		request = append(request, r.Form.Encode())
	}
	// Return the request as a string
	return strings.Join(request, "\n")
}

func myFormatter(r *http.Request) (*http.Request, APIErrorCode){
	fmt.Println("\n\n\nIncoming Request\n\n")
	fmt.Println(printRequest(r))
	r, err := formattingRequest(r)
	fmt.Println("\n\nAfter Formatting\n\n")
	fmt.Println(printRequest(r))
	return r, err
}
