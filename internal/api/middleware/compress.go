package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		writer, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return writer
	},
}

type gzipResponseWriter struct {
	http.ResponseWriter
	writer *gzip.Writer
}

func (grw *gzipResponseWriter) Write(data []byte) (int, error) {
	return grw.writer.Write(data)
}

func CompressMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !strings.Contains(request.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(writer, request)
			return
		}

		gzWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzWriter.Reset(writer)
		defer func() {
			gzWriter.Close()
			gzipWriterPool.Put(gzWriter)
		}()

		writer.Header().Set("Content-Encoding", "gzip")
		writer.Header().Del("Content-Length")

		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: writer, writer: gzWriter}, request)
	})
}
