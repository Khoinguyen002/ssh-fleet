package hub

import (
	"net/http"

	"ssh-fleet/internal/ws"
)

type WSConn = ws.Conn

func UpgradeWebSocket(w http.ResponseWriter, r *http.Request) (*WSConn, error) {
	return ws.UpgradeServer(w, r)
}
