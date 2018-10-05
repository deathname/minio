package cmd

import (
	"net/url"
)
type fields struct{
	config_name string
	instance_id string
	hashVal string
}

func DfferentiateRequest(r *url.URL)(*url.URL){
	query := r.String()
	query = "/525278-shakti-dirtree" + query
	r, _ = url.Parse(query)
	return r
}