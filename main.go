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
	apiRouter.HandleFunc("/reset", apiCfg.resetHandler)
	apiRouter.Post("/chirps", postChirpsHandler)
	apiRouter.Get("/chirps", getChirpsHandler)
	apiRouter.Get("/chirps/{chirpID}", getSingleChirpHandler)
	r.Mount("/api", apiRouter)

	adminRouter := chi.NewRouter()
	adminRouter.Get("/metrics", apiCfg.hitsHandler)

	r.Mount("/admin", adminRouter)

	logMux := middlewareLog(r)
	corsMux := middlewareCors(logMux)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: corsMux,
	}
	log.Printf("Serving on port: %s\n", port)
	log.Fatal(srv.ListenAndServe())

}
