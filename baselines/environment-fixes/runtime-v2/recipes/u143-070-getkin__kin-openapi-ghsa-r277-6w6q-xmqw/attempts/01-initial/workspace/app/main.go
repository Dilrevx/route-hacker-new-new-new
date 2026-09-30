package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/getkin/kin-openapi/openapi3filter"
)

func main() {
	specFile := os.Getenv("OPENAPI_SPEC")
	if specFile == "" {
		specFile = "openapi.yaml"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	r := mux.NewRouter()
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	}).Methods("GET")

	r.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"users": []interface{}{}})
	}).Methods("GET")

	r.HandleFunc("/api/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"user": map[string]string{"id": vars["id"]}})
	}).Methods("GET")

	validationHandler := &openapi3filter.ValidationHandler{
		Handler: r,
		File:    specFile,
	}

	if err := validationHandler.Load(); err != nil {
		log.Fatalf("Failed to load OpenAPI spec: %v", err)
	}

	log.Printf("Starting server on port %s", port)
	if err := http.ListenAndServe(":"+port, validationHandler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
