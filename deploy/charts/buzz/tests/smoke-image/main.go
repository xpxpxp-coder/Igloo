// Command snowman-chart-smoke provides only the container endpoints needed to
// prove the Snowman Command Center Helm chart can become Ready in a disposable
// kind cluster. It deliberately contains no relay, provider, or customer-data
// behavior and is built and loaded locally by the chart workflow.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const shutdownTimeout = 5 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errorsCh := make(chan error, 3)
	servers := []*http.Server{
		newServer(":3000", applicationHandler()),
		newServer(":8080", healthHandler()),
		newServer(":9102", metricsHandler()),
	}

	for _, server := range servers {
		go serve(server, errorsCh)
	}

	select {
	case <-ctx.Done():
	case err := <-errorsCh:
		fmt.Fprintf(os.Stderr, "chart smoke server failed: %v\n", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "chart smoke server shutdown failed: %v\n", err)
		}
	}
}

func newServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}

func serve(server *http.Server, errorsCh chan<- error) {
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errorsCh <- err
	}
}

func applicationHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("snowman command center chart smoke\n"))
	})
	return mux
}

func healthHandler() http.Handler {
	mux := http.NewServeMux()
	for _, path := range []string{"/_liveness", "/_readiness"} {
		mux.HandleFunc(path, func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "text/plain; charset=utf-8")
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte("ok\n"))
		})
	}
	return mux
}

func metricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain; version=0.0.4")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("snowman_chart_smoke_ready 1\n"))
	})
	return mux
}
