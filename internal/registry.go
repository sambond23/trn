package internal

import (
	"crypto/ed25519"
	"sync"
	"time"
	"trn/proto/directory"
)

type NodeInfo struct {
	ID        uint32
	Address   string
	PublicKey ed25519.PublicKey
	X25519Pub [32]byte
	NodeType  string
	Active    bool
	Country   string
	City      string
	Load      float64
	LastSeen  time.Time
}

type Registry struct {
	mu    sync.RWMutex
	nodes map[uint32]*NodeInfo
}

func NewRegistry() *Registry {
	return &Registry{nodes: make(map[uint32]*NodeInfo)}
}

func (r *Registry) AddOrUpdate(info *NodeInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.nodes[info.ID]
	if !ok || info.LastSeen.After(existing.LastSeen) {
		r.nodes[info.ID] = info
	}
}

func (r *Registry) GetNode(id uint32) (*NodeInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.nodes[id]
	return n, ok
}

func (r *Registry) GetNodes(role, country string) []*NodeInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var res []*NodeInfo
	for _, n := range r.nodes {
		if !n.Active || time.Since(n.LastSeen) > 30*time.Second {
			continue
		}
		if role != "" && n.NodeType != role {
			continue
		}
		if country != "" && n.Country != country {
			continue
		}
		res = append(res, n)
	}
	return res
}

func (r *Registry) GetAllNodes() []*NodeInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var res []*NodeInfo
	for _, n := range r.nodes {
		if n.Active && time.Since(n.LastSeen) <= 30*time.Second {
			res = append(res, n)
		}
	}
	return res
}

func (n *NodeInfo) ToProto() *directory.NodeInfo {
	return &directory.NodeInfo{
		Id:        n.ID,
		Address:   n.Address,
		PublicKey: n.PublicKey,
		X25519Pub: n.X25519Pub[:],
		NodeType:  n.NodeType,
		Active:    n.Active,
		Country:   n.Country,
		City:      n.City,
		Load:      n.Load,
		LastSeen:  n.LastSeen.Unix(),
	}
}

func FromProto(pb *directory.NodeInfo) *NodeInfo {
	var x25519 [32]byte
	copy(x25519[:], pb.X25519Pub)
	return &NodeInfo{
		ID:        pb.Id,
		Address:   pb.Address,
		PublicKey: pb.PublicKey,
		X25519Pub: x25519,
		NodeType:  pb.NodeType,
		Active:    pb.Active,
		Country:   pb.Country,
		City:      pb.City,
		Load:      pb.Load,
		LastSeen:  time.Unix(pb.LastSeen, 0),
	}
}
