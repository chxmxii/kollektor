package node

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/chxmxii/kollektor/internal/archive"
)

// Socket is one entry of /proc/net/{tcp,udp,raw}[6] in some network
// namespace, with the processes holding it.
type Socket struct {
	NetNS  string `json:"netns"`
	Proto  string `json:"proto"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	State  string `json:"state"`
	UID    int    `json:"uid"`
	Inode  uint64 `json:"inode"`
	PIDs   []int  `json:"pids,omitempty"`
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

var socketTables = []string{"tcp", "tcp6", "udp", "udp6", "raw", "raw6"}

// collectSockets lists sockets in every network namespace on the node (host
// and each pod), so connections made from inside pods are visible too.
func collectSockets(_ context.Context, opts Options, w *archive.Writer, log *slog.Logger) error {
	pids, err := listPIDs(opts.ProcRoot)
	if err != nil {
		w.RecordError("sockets: %v", err)
		return nil
	}

	owners := map[uint64][]int{} // socket inode → pids
	nsPID := map[string]int{}    // netns → one pid inside it
	for _, pid := range pids {
		dir := filepath.Join(opts.ProcRoot, strconv.Itoa(pid))
		if ns, err := os.Readlink(filepath.Join(dir, "ns", "net")); err == nil {
			if _, ok := nsPID[ns]; !ok {
				nsPID[ns] = pid
			}
		}
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			l, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]"), 10, 64)
			if err == nil {
				owners[ino] = appendUnique(owners[ino], pid)
			}
		}
	}

	var sockets []Socket
	for ns, pid := range nsPID {
		for _, table := range socketTables {
			f, err := os.Open(filepath.Join(opts.ProcRoot, strconv.Itoa(pid), "net", table))
			if err != nil {
				continue
			}
			socks, err := parseSocketTable(f, table)
			f.Close()
			if err != nil {
				w.RecordError("sockets %s %s: %v", ns, table, err)
				continue
			}
			for i := range socks {
				socks[i].NetNS = ns
				socks[i].PIDs = owners[socks[i].Inode]
			}
			sockets = append(sockets, socks...)
		}
	}
	log.Info("socket snapshot", "netns", len(nsPID), "sockets", len(sockets))
	return w.WriteJSON("network/sockets.json", sockets)
}

// parseSocketTable parses the /proc/net/{tcp,udp,raw}[6] format:
//
//	sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode ...
func parseSocketTable(r io.Reader, proto string) ([]Socket, error) {
	var out []Socket
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		local, err := parseHexAddr(f[1])
		if err != nil {
			return nil, err
		}
		remote, err := parseHexAddr(f[2])
		if err != nil {
			return nil, err
		}
		state := f[3]
		if strings.HasPrefix(proto, "tcp") {
			if s, ok := tcpStates[strings.ToUpper(state)]; ok {
				state = s
			}
		}
		uid, _ := strconv.Atoi(f[7])
		ino, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Socket{Proto: proto, Local: local, Remote: remote, State: state, UID: uid, Inode: ino})
	}
	return out, sc.Err()
}

// parseHexAddr decodes "0100007F:0035" (IPv4) or a 32-hex-digit IPv6 address
// with port. Addresses are stored as 32-bit words in host (little-endian)
// byte order.
func parseHexAddr(s string) (string, error) {
	addrHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return "", fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", fmt.Errorf("bad address %q", s)
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", fmt.Errorf("bad port %q", s)
	}
	return net.JoinHostPort(net.IP(raw).String(), strconv.FormatUint(port, 10)), nil
}

func appendUnique(s []int, v int) []int {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
