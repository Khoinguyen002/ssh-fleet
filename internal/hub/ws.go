package hub

import (
	"net/http"

	"ssh-fleet/internal/ws"
)

type WSConn = ws.Conn

func UpgradeWebSocket(w http.ResponseWriter, r *http.Request) (*WSConn, error) {
	return ws.UpgradeServer(w, r)
}

func UpgradeWebSocketWithOptions(w http.ResponseWriter, r *http.Request, opts ws.UpgradeOptions) (*WSConn, error) {
	return ws.UpgradeServerWithOptions(w, r, opts)
}
