package main

import (
	"errors"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/jlinke1/chirpy/internal/database"
)

type apiConfig struct {
	fileServerHits int
	DB             *database.DB
	jwtSecret      string
}

func main() {
	const dbFileName = "database.json"
	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()
	if *dbg {
		err := os.Remove(dbFileName)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Fatal(err)
		}
	}

	const filePathRoot = "."
	const port = "8080"

	db, err := database.NewDB(dbFileName)
	if err != nil {
		log.Fatal(err)
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	apiCfg := apiConfig{
		fileServerHits: 0,
		DB:             db,
		jwtSecret:      jwtSecret,
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
	apiRouter.Post("/login", apiCfg.postLoginHandler)
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
