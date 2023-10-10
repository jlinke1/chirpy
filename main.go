package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func main() {
	const filePathRoot = "."
	const port = "8080"

	apiCfg := apiConfig{}
	r := chi.NewRouter()
	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filePathRoot))))
	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)

	apiRouter := chi.NewRouter()
	apiRouter.Get("/healthz", healthzHandler)
	apiRouter.Get("/metrics", apiCfg.hitsHandler)
	apiRouter.HandleFunc("/reset", apiCfg.resetHandler)

	r.Mount("/api", apiRouter)

	logMux := middlewareLog(r)
	corsMux := middlewareCors(logMux)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: corsMux,
	}
	log.Printf("Serving on port: %s\n", port)
	log.Fatal(srv.ListenAndServe())

}
