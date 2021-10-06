package api

import (
	"os"
	"path"

	"github.com/IpsoVeritas/httphandler"
	"github.com/IpsoVeritas/proxy/pkg/version"

	"net/http"
)

// Version returns the servers version
func Version(req httphandler.Request) httphandler.Response {
	return httphandler.NewStandardResponse(http.StatusOK, "text/plain", path.Base(os.Args[0])+"/"+version.Version)
}
