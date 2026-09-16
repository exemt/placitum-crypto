package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/exemt/placitum-crypto/internal/certmeta"
	"github.com/exemt/placitum-crypto/internal/contourkey"
	"github.com/exemt/placitum-crypto/internal/envelope"
)

type Deps struct {
	Key           *contourkey.Key
	ControllerURL string
	Client        *http.Client
	Log           *slog.Logger
}

func Handler(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("POST /v1/certificates/metadata", metadata(d))
	mux.HandleFunc("POST /v1/crl/metadata", crlMetadata(d))

	return mux
}

type metadataRequest struct {
	Scope        string  `json:"scope"`
	CertStoreID  string  `json:"cert_store_id"`
	KeyStoreID   *string `json:"key_store_id"`
	ChainStoreID *string `json:"chain_store_id"`
}

type metadataResponse struct {
	SANs        []string `json:"sans"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	Fingerprint string   `json:"fingerprint"`
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	Serial      string   `json:"serial"`
	IsCA        bool     `json:"is_ca"`
}

type crlRequest struct {
	Scope      string `json:"scope"`
	CRLStoreID string `json:"crl_store_id"`
}

type crlResponse struct {
	Issuer     string `json:"issuer"`
	ThisUpdate string `json:"this_update"`
	NextUpdate string `json:"next_update"`
	Revoked    int    `json:"revoked"`
}

func metadata(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Key == nil {
			writeError(w, http.StatusServiceUnavailable, "key_unavailable")
			return
		}

		var req metadataRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json")
			return
		}

		if !isUUID(req.Scope) || !isUUID(req.CertStoreID) ||
			(req.KeyStoreID != nil && !isUUID(*req.KeyStoreID)) ||
			(req.ChainStoreID != nil && !isUUID(*req.ChainStoreID)) {
			writeError(w, http.StatusBadRequest, "invalid_uuid")
			return
		}

		certPEM, ok := fetchAndOpen(w, r.Context(), d, req.Scope, req.CertStoreID)
		if !ok {
			return
		}

		if req.ChainStoreID != nil {
			chainPEM, ok := fetchAndOpen(w, r.Context(), d, req.Scope, *req.ChainStoreID)
			if !ok {
				return
			}

			if err := certmeta.ParseChain(chainPEM); err != nil {
				writeError(w, http.StatusUnprocessableEntity, "invalid_certificate")
				return
			}
		}

		meta, err := certmeta.ParseCertificate(certPEM)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid_certificate")
			return
		}

		if req.KeyStoreID != nil {
			keyPEM, ok := fetchAndOpen(w, r.Context(), d, req.Scope, *req.KeyStoreID)
			if !ok {
				return
			}

			if err := certmeta.MatchesKey(certPEM, keyPEM); err != nil {
				if errors.Is(err, certmeta.ErrKeyMismatch) {
					writeError(w, http.StatusUnprocessableEntity, "key_mismatch")
				} else {
					writeError(w, http.StatusUnprocessableEntity, "invalid_certificate")
				}
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadataResponse{
			SANs:        meta.SANs,
			NotBefore:   meta.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:    meta.NotAfter.UTC().Format(time.RFC3339),
			Fingerprint: meta.Fingerprint,
			Subject:     meta.Subject,
			Issuer:      meta.Issuer,
			Serial:      meta.Serial,
			IsCA:        meta.IsCA,
		})
	}
}

func crlMetadata(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Key == nil {
			writeError(w, http.StatusServiceUnavailable, "key_unavailable")
			return
		}

		var req crlRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json")
			return
		}

		if !isUUID(req.Scope) || !isUUID(req.CRLStoreID) {
			writeError(w, http.StatusBadRequest, "invalid_uuid")
			return
		}

		crlPEM, ok := fetchAndOpen(w, r.Context(), d, req.Scope, req.CRLStoreID)
		if !ok {
			return
		}

		meta, err := certmeta.ParseCRL(crlPEM)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid_crl")
			return
		}

		nextUpdate := ""
		if !meta.NextUpdate.IsZero() {
			nextUpdate = meta.NextUpdate.UTC().Format(time.RFC3339)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(crlResponse{
			Issuer:     meta.Issuer,
			ThisUpdate: meta.ThisUpdate.UTC().Format(time.RFC3339),
			NextUpdate: nextUpdate,
			Revoked:    meta.Revoked,
		})
	}
}

func fetchAndOpen(
	w http.ResponseWriter,
	ctx context.Context,
	d Deps,
	scope, uuid string,
) ([]byte, bool) {
	blob, err := fetchBlob(ctx, d, scope, uuid)
	if err != nil {
		writeFetchError(w, d.Log, err)
		return nil, false
	}

	plaintext, err := envelope.Open(blob, d.Key.Private)
	if err != nil {
		d.Log.Warn("open envelope failed", "uuid", uuid, "error", err.Error())
		writeError(w, http.StatusUnprocessableEntity, "undecryptable")
		return nil, false
	}

	return plaintext, true
}

var errStoreNotFound = errors.New("store object not found")

func fetchBlob(ctx context.Context, d Deps, scope, uuid string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/%s/store/%s/blob", d.ControllerURL, scope, uuid)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errStoreNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("controller store: unexpected status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func writeFetchError(w http.ResponseWriter, log *slog.Logger, err error) {
	if errors.Is(err, errStoreNotFound) {
		writeError(w, http.StatusNotFound, "store_object_not_found")
		return
	}

	log.Warn("controller unreachable", "error", err.Error())
	writeError(w, http.StatusBadGateway, "controller_unreachable")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}

	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}

		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	return true
}
