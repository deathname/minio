package cmd

import (
	"net/http"
	"fmt"
	"time"
	"strings"
	"github.com/minio/minio-go/pkg/s3utils"
	"encoding/hex"
	"crypto/sha256"
	//"net/url"
)

func credentialHeaderParser(credElement string, region string) (ch credentialHeader, aec APIErrorCode) {
	creds := strings.Split(strings.TrimSpace(credElement), "=")
	if len(creds) != 2 {
		return ch, ErrMissingFields
	}
	if creds[0] != "Credential" {
		return ch, ErrMissingCredTag
	}
	credElements := strings.Split(strings.TrimSpace(creds[1]), "/")
	if len(credElements) != 5 {
		return ch, ErrCredMalformed
	}

	cred := credentialHeader{
		accessKey: globalServerConfig.GetCredential().AccessKey,
	}
	var e error
	cred.scope.date, e = time.Parse(yyyymmdd, credElements[1])
	if e != nil {
		return ch, ErrMalformedCredentialDate
	}

	cred.scope.region = credElements[2]
	sRegion := cred.scope.region
	if region == "" {
		region = sRegion
	}
	// Should validate region, only if region is set.
	//if !isValidRegion(sRegion, region) {
	//	return ch, ErrAuthorizationHeaderMalformed
	//
	//}
	if credElements[3] != "s3" {
		return ch, ErrInvalidService
	}
	cred.scope.service = credElements[3]
	if credElements[4] != "aws4_request" {
		return ch, ErrInvalidRequestVersion
	}
	cred.scope.request = credElements[4]
	return cred, ErrNone
}

func parseAuthHeader(v4Auth, region string)(sv signValues,ace APIErrorCode){
	v4Auth = strings.Replace(v4Auth, " ", "", -1)
	if v4Auth == "" {
		return sv, ErrAuthHeaderEmpty
	}

	if !strings.HasPrefix(v4Auth, signV4Algorithm) {
		return sv, ErrSignatureVersionNotSupported
	}

	v4Auth = strings.TrimPrefix(v4Auth, signV4Algorithm)
	authFields := strings.Split(strings.TrimSpace(v4Auth), ",")
	if len(authFields) != 3 {
		return sv, ErrMissingFields
	}

	signV4Values := signValues{}

	var err APIErrorCode
	// Save credentail values.
	signV4Values.Credential, err = credentialHeaderParser(authFields[0], region)


	if err != ErrNone {
		return sv, err
	}

	// Save signed headers.
	signV4Values.SignedHeaders, err = parseSignedHeader(authFields[1])
	//All Signed Header in array
	if err != ErrNone {
		return sv, err
	}

	// Save signature.
	signV4Values.Signature, err = parseSignature(authFields[2])
	if err != ErrNone {
		return sv, err
	}
	//we have signature

	// Return the structure here.
	return signV4Values, ErrNone
}

func v4ToString(s signValues) string{

	algo := signV4Algorithm
	credArray := make([]string,5)
	credArray[0] = s.Credential.accessKey
	credArray[1] = (s.Credential.scope.date).Format("20060102")
	credArray[2] = s.Credential.scope.region
	credArray[3] = s.Credential.scope.service
	credArray[4] = s.Credential.scope.request
	x := strings.Join(credArray,"/")
	cred := "Credential="+x + ","
	x = strings.Join(s.SignedHeaders, ";")
	signHeader := "SignedHeaders=" + x + ","
	sign := "Signature=" + s.Signature
	return algo + " " + cred + " " + signHeader + " " + sign
}

func getRequiredRequest(extractedSignedHeaders http.Header, payload, queryStr, urlPath, method string) string {
	fmt.Println("getCanonicalRequest\n\n")

	rawQuery := strings.Replace(queryStr, "+", "%20", -1)
	encodedPath := s3utils.EncodePath(urlPath)
	canonicalRequest := strings.Join([]string{
		method,
		encodedPath,
		rawQuery,
		getCanonicalHeaders(extractedSignedHeaders),
		getSignedHeaders(extractedSignedHeaders),
		payload,
	}, "\n")
	return canonicalRequest
}

func stringToSign(canonicalRequest string, t time.Time, scope string) string {
	stringToSign := signV4Algorithm + "\n" + t.Format(iso8601Format) + "\n"
	stringToSign = stringToSign + scope + "\n"
	canonicalRequestBytes := sha256.Sum256([]byte(canonicalRequest))
	stringToSign = stringToSign + hex.EncodeToString(canonicalRequestBytes[:])
	return stringToSign
}

func signingKey(secretKey string, t time.Time, region string) []byte {
	date := sumHMAC([]byte("AWS4"+secretKey), []byte(t.Format(yyyymmdd)))
	regionBytes := sumHMAC(date, []byte(region))
	service := sumHMAC(regionBytes, []byte("s3"))
	signingKey := sumHMAC(service, []byte("aws4_request"))
	return signingKey
}


func getFinalSignature(signingKey []byte, stringToSign string) string {
	return hex.EncodeToString(sumHMAC(signingKey, []byte(stringToSign)))
}


func signV4parser(r *http.Request, region string, hashedPayload string) APIErrorCode{
	cred := globalServerConfig.GetCredential()


	v4Auth := r.Header.Get("Authorization")
	signV4Values, err := parseAuthHeader(v4Auth, region)

	fmt.Println(signV4Values)

	if err != ErrNone {
		return err
	}

	extractedSignedHeaders, errCode := extractSignedHeaders(signV4Values.SignedHeaders, r)
	if errCode != ErrNone {
		return errCode
	}

	if signV4Values.Credential.accessKey != cred.AccessKey {
		return ErrInvalidAccessKeyID
	}

	var date string
	if date = r.Header.Get(http.CanonicalHeaderKey("x-amz-date")); date == "" {
		if date = r.Header.Get("Date"); date == "" {
			return ErrMissingDateHeader
		}
	}
	t, e := time.Parse(iso8601Format, date)
	if e != nil {
		return ErrMalformedDate
	}

	queryStr := r.URL.Query().Encode()

	canonicalRequest := getRequiredRequest(extractedSignedHeaders, hashedPayload, queryStr, r.URL.Path, r.Method)

	stringToSign := stringToSign(canonicalRequest, t, signV4Values.Credential.getScope())

	signingKey := signingKey(cred.SecretKey, signV4Values.Credential.scope.date, signV4Values.Credential.scope.region)

	newSignature := getFinalSignature(signingKey, stringToSign)
	fmt.Println("#### SIGNATURE #####")
	fmt.Println(newSignature)
	signV4Values.Signature = newSignature

	signV4toString := v4ToString(signV4Values)
	fmt.Println(signV4toString)
	r.Header.Set("Authorization",signV4toString)
	// Return error none.
	return ErrNone
}


func RequestFormatterV4(r *http.Request,region string, hashedPayload string){
	fmt.Println("Incoming Formatting :- ")
	//fmt.Println(printRequest(r))
	signV4parser(r,region,hashedPayload)
	fmt.Println("\n\nAfter Formatting")
	fmt.Println(printRequest(r))
}
