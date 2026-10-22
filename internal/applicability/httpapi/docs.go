package httpapi

import (
	_ "embed"
	"net/http"

	swaggerFiles "github.com/swaggo/files"
)

const (
	openAPIPath = "/api/v1/analysis/openapi.json"
	docsPrefix  = "/api/v1/analysis/docs"
)

//go:embed openapi.json
var openAPISpec []byte

func serveOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openAPISpec)
}

func redirectDocs(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, docsPrefix+"/", http.StatusFound)
}

var swaggerIndexHTML = []byte(`<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Анализ применимости — Swagger</title>
  <link rel="stylesheet" href="./swagger-ui.css">
  <link rel="icon" type="image/png" href="./favicon-32x32.png" sizes="32x32">
  <style>
    html { box-sizing: border-box; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="./swagger-ui-bundle.js"></script>
  <script src="./swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function () {
      window.ui = SwaggerUIBundle({
        url: "` + openAPIPath + `",
        dom_id: "#swagger-ui",
        deepLinking: true,
        docExpansion: "list",
        defaultModelsExpandDepth: 1,
        displayRequestDuration: true,
        validatorUrl: null,
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>
`)

func mountDocs(mux *http.ServeMux) {
	mux.HandleFunc("GET "+openAPIPath, serveOpenAPI)
	mux.HandleFunc("GET "+docsPrefix, redirectDocs)
	// {$} matches only this path. A bare trailing slash would also match
	// /api/v1/analysis/docs/report and clash with /api/v1/analysis/{id}/report.
	mux.HandleFunc("GET "+docsPrefix+"/{$}", serveSwaggerIndex)
	mux.HandleFunc("GET "+docsPrefix+"/index.html", serveSwaggerIndex)
	for _, name := range []string{
		"swagger-ui.css",
		"swagger-ui-bundle.js",
		"swagger-ui-standalone-preset.js",
		"favicon-32x32.png",
		"favicon-16x16.png",
	} {
		mux.HandleFunc("GET "+docsPrefix+"/"+name, serveSwaggerAsset(name))
	}
}

func serveSwaggerIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(swaggerIndexHTML)
}

func serveSwaggerAsset(name string) http.HandlerFunc {
	files := http.FileServer(swaggerFiles.HTTP)
	return func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.URL.Path = "/" + name
		files.ServeHTTP(w, clone)
	}
}
