package internal

import (
	"context"
	"log"
	"math/rand"
	"sync"
	"time"
	"trn/proto/directory"

	"google.golang.org/grpc"
)

type Gossip struct {
	mu       sync.RWMutex
	nodeID   uint32
	registry *Registry
	peers    []string
	stopCh   chan struct{}
}

func NewGossip(nodeID uint32, reg *Registry, bootPeers []string) *Gossip {
	g := &Gossip{
		nodeID:   nodeID,
		registry: reg,
		peers:    bootPeers,
		stopCh:   make(chan struct{}),
	}
	go g.loop()
	return g
}

func (g *Gossip) loop() {
	ticker := time.NewTicker(15 * time.Second)
	for {
		select {
		case <-ticker.C:
			g.gossipOnce()
		case <-g.stopCh:
			return
		}
	}
}

func (g *Gossip) gossipOnce() {
	g.mu.RLock()
	peers := make([]string, len(g.peers))
	copy(peers, g.peers)
	g.mu.RUnlock()
	if len(peers) == 0 {
		return
	}
	idx := rand.Intn(len(peers))
	peerAddr := peers[idx]
	conn, err := grpc.Dial(peerAddr, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(3*time.Second))
	if err != nil {
		return
	}
	defer conn.Close()
	client := directory.NewDirectoryClient(conn)
	resp, err := client.SyncRegistry(context.Background(), &directory.SyncRequest{NodeId: g.nodeID})
	if err != nil {
		return
	}
	other := NewRegistry()
	for _, pb := range resp.Nodes {
		other.AddOrUpdate(FromProto(pb))
	}
	g.registry.Merge(other)
	log.Printf("[Gossip] merged from %s", peerAddr)
}

func (g *Gossip) AddPeer(addr string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, p := range g.peers {
		if p == addr {
			return
		}
	}
	g.peers = append(g.peers, addr)
}

func (r *Registry) Merge(other *Registry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, info := range other.nodes {
		if existing, ok := r.nodes[id]; !ok || info.LastSeen.After(existing.LastSeen) {
			r.nodes[id] = info
		}
	}
}
