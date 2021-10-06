module github.com/IpsoVeritas/proxy

go 1.16

replace github.com/IpsoVeritas/document => ../document

replace github.com/IpsoVeritas/httphandler => ../httphandler

replace github.com/IpsoVeritas/crypto => ../crypto

replace github.com/IpsoVeritas/logger => ../logger

require (
	github.com/IpsoVeritas/crypto v0.0.0-20181010203950-c229a2b23e68
	github.com/IpsoVeritas/document v0.0.0-20180814075806-099bc71d4b53
	github.com/IpsoVeritas/httphandler v0.0.0-20181212145926-bf993b3ad528
	github.com/IpsoVeritas/logger v0.0.0-20180912100710-b76d97958f28
	github.com/gorilla/websocket v1.4.2
	github.com/joho/godotenv v1.3.0
	github.com/julienschmidt/httprouter v1.3.0
	github.com/pkg/errors v0.9.1
	github.com/satori/go.uuid v1.2.0
	github.com/spf13/viper v1.8.1
	github.com/tylerb/graceful v1.2.15
	github.com/ulule/limiter v2.2.2+incompatible
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e // indirect
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	gopkg.in/square/go-jose.v1 v1.1.2
)
