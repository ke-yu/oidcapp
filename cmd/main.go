package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/kit/log"
	appconfig "github.com/keyu/oidcapp/config"
	"github.com/keyu/oidcapp/internal/server"
)

func main() {
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	config := appconfig.GetConfiguration()
	server := server.NewServer(logger, config)

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	go func() {
		logger.Log("msg", fmt.Sprintf("start HTTP server at %v", config.Addr))
		errs <- http.ListenAndServe(config.Addr, server)
	}()
	logger.Log(fmt.Sprintf("Exit: %v", <-errs))
}
