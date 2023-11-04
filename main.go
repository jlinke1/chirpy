package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jlinke1/chirpy/internal/database"
)

type apiConfig struct {
	fileServerHits int
	DB             *database.DB
}

func main() {
	const filePathRoot = "."
	const port = "8080"

	db, err := database.NewDB("database.json")
	if err != nil {
		log.Fatal(err)
	}

	apiCfg := apiConfig{
		fileServerHits: 0,
		DB:             db,
	}
	r := chi.NewRouter()
	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filePathRoot))))
	r.Handle("/app/*", fsHandler)
	r.Handle("/app", fsHandler)

	apiRouter := chi.NewRouter()
	apiRouter.Get("/healthz", healthzHandler)
	apiRouter.HandleFunc("/reset", apiCfg.resetHandler)
	apiRouter.Post("/chirps", apiCfg.postChirpsHandler)
	apiRouter.Get("/chirps", apiCfg.getChirpsHandler)
	apiRouter.Get("/chirps/{chirpID}", apiCfg.getSingleChirpHandler)
	apiRouter.Post("/users", apiCfg.postUsersHandler)
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
