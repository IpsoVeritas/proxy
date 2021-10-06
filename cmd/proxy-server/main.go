package main

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/IpsoVeritas/logger"
	"github.com/IpsoVeritas/proxy/pkg/server/clients"
	"github.com/IpsoVeritas/proxy/pkg/version"

	"path"

	"github.com/IpsoVeritas/httphandler"
	"github.com/IpsoVeritas/proxy/pkg/server/api"
	"github.com/joho/godotenv"
	"github.com/spf13/viper"
	"github.com/tylerb/graceful"

	"github.com/ulule/limiter"
	"github.com/ulule/limiter/drivers/store/memory"
)

func main() {
	_ = godotenv.Load(".env")
	viper.AutomaticEnv()
	viper.SetDefault("log_formatter", "text")
	viper.SetDefault("log_level", "debug")
	viper.SetDefault("addr", ":6519")
	viper.SetDefault("base", "http://localhost:6519")
	viper.SetDefault("domain", "")

	logger.SetOutput(os.Stdout)
	logger.SetFormatter(viper.GetString("log_formatter"))
	logger.SetLevel(viper.GetString("log_level"))
	logger.AddContext("service", path.Base(os.Args[0]))
	logger.AddContext("version", version.Version)

	addr := viper.GetString("addr")
	server := &graceful.Server{
		Timeout: time.Duration(15) * time.Second,
		Server: &http.Server{
			Addr:    addr,
			Handler: loadHandler(),
		},
	}

	logger.Infof("Server with version %s starting at %s", version.Version, addr)
	if err := server.ListenAndServe(); err != nil {
		logger.Fatal(err)
	}
}

func loadHandler() http.Handler {

	wrappers := httphandler.NewWrapper(false)

	clients := clients.New()

	r := httphandler.NewRouter()
	r.GET("/", wrappers.Wrap(api.Version))

	subscribeController := api.NewSubscribeController(viper.GetString("domain"), clients)
	r.GET("/proxy/subscribe", subscribeController.SubscribeHandler)

	apiHandler := httphandler.LoadMiddlewares(r, version.Version)

	store, err := loadLimiterStore()
	if err != nil {
		logger.Fatal(err)
	}
	limiter := limiter.New(store, limiter.Rate{
		Period: 5 * time.Minute,
		Limit:  500,
	})
	requestHandler := httphandler.NewRouter()
	requestController := api.NewRequestController(viper.GetString("domain"), clients, limiter)
	requestHandler.GET("/proxy/request/:clientID/*filepath", requestController.Handle)
	requestHandler.POST("/proxy/request/:clientID/*filepath", requestController.Handle)
	requestHandler.PUT("/proxy/request/:clientID/*filepath", requestController.Handle)
	requestHandler.DELETE("/proxy/request/:clientID/*filepath", requestController.Handle)
	requestHandler.OPTIONS("/proxy/request/:clientID/*filepath", requestController.Handle)

	domainHandler := httphandler.NewRouter()
	if viper.GetString("domain") != "" {
		domainHandler.GET("/*filepath", requestController.Handle)
		domainHandler.POST("/*filepath", requestController.Handle)
		domainHandler.PUT("/*filepath", requestController.Handle)
		domainHandler.DELETE("/*filepath", requestController.Handle)
		domainHandler.OPTIONS("/*filepath", requestController.Handle)
	}

	return &requestRouter{
		domain:         viper.GetString("domain"),
		apiHandler:     apiHandler,
		requestHandler: requestHandler,
		domainHandler:  domainHandler,
	}
}

type requestRouter struct {
	domain         string
	apiHandler     http.Handler
	requestHandler http.Handler
	domainHandler  http.Handler
}

func (d *requestRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if d.domain != "" && strings.HasSuffix(host, "."+d.domain) {
		d.domainHandler.ServeHTTP(w, req)
	} else {
		if strings.HasPrefix(req.URL.Path, "/proxy/request/") {
			d.requestHandler.ServeHTTP(w, req)
		} else {
			d.apiHandler.ServeHTTP(w, req)
		}
	}
}

func loadLimiterStore() (limiter.Store, error) {
	return memory.NewStore(), nil
}
