package internal

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"sync"
	"time"
	"trn/proto/directory"

	"google.golang.org/grpc"
)

type NodeRole string

const (
	RoleEntry NodeRole = "entry"
	RoleMid   NodeRole = "mid"
	RoleExit  NodeRole = "exit"
	RoleIdle  NodeRole = "idle"
)

// ---------- Module interface ----------
type Module interface {
	Start(addr string) error
	Stop()
	HandlePacket(data []byte, clientAddr net.Addr) error
}

// ---------- EntryModule ----------
type EntryModule struct {
	sessionStore *SessionStore
	addrMap      map[uint32]string
	conn         net.Conn
	transport    string
	certFile     string
	keyFile      string
	listener     net.Listener
}

func NewEntryModule(store *SessionStore, addrMap map[uint32]string, transport, certFile, keyFile string) *EntryModule {
	return &EntryModule{
		sessionStore: store,
		addrMap:      addrMap,
		transport:    transport,
		certFile:     certFile,
		keyFile:      keyFile,
	}
}

func (e *EntryModule) Start(addr string) error {
	if e.transport == "tls" {
		cert, err := tls.LoadX509KeyPair(e.certFile, e.keyFile)
		if err != nil {
			return err
		}
		config := &tls.Config{Certificates: []tls.Certificate{cert}}
		listener, err := tls.Listen("tcp", addr, config)
		if err != nil {
			return err
		}
		e.listener = listener
		go e.acceptTLS()
	} else {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		e.conn = conn
		go e.listenUDP()
	}
	return nil
}

func (e *EntryModule) Stop() {
	if e.conn != nil {
		e.conn.Close()
	}
	if e.listener != nil {
		e.listener.Close()
	}
}

func (e *EntryModule) listenUDP() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := e.conn.(*net.UDPConn).ReadFromUDP(buf)
		if err != nil {
			break
		}
		go e.HandlePacket(buf[:n], addr)
	}
}

func (e *EntryModule) acceptTLS() {
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			break
		}
		go e.handleTLS(conn)
	}
}

func (e *EntryModule) handleTLS(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 65536)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		e.HandlePacket(buf[:n], conn.RemoteAddr())
	}
}

func (e *EntryModule) HandlePacket(data []byte, clientAddr net.Addr) error {
	pkt, err := UnmarshalPacket(data)
	if err != nil {
		return err
	}
	if pkt.HopIndex != 0 {
		return errors.New("not entry hop")
	}
	sess, err := e.sessionStore.Get(pkt.SessionID)
	if err != nil {
		return err
	}
	plain, err := DecryptLayer(sess.Keys[0], pkt.Payload)
	if err != nil {
		return err
	}
	nextID, ok := pkt.NextHopID()
	if !ok {
		return errors.New("no next hop")
	}
	nextAddr, ok := e.addrMap[nextID]
	if !ok {
		return errors.New("next hop address unknown")
	}
	newPkt := &Packet{
		Version:        pkt.Version,
		HopIndex:       pkt.HopIndex + 1,
		TotalHops:      pkt.TotalHops,
		Flags:          pkt.Flags,
		SessionID:      pkt.SessionID,
		RouteVector:    pkt.RouteVector,
		FragmentID:     pkt.FragmentID,
		TotalFragments: pkt.TotalFragments,
		PayloadLen:     uint16(len(plain)),
		Payload:        plain,
	}
	conn, err := net.Dial("udp", nextAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(newPkt.Marshal())
	return err
}

// ---------- MidModule ----------
type MidModule struct {
	sessionStore *SessionStore
	addrMap      map[uint32]string
	conn         net.Conn
	transport    string
	certFile     string
	keyFile      string
	listener     net.Listener
}

func NewMidModule(store *SessionStore, addrMap map[uint32]string, transport, certFile, keyFile string) *MidModule {
	return &MidModule{
		sessionStore: store,
		addrMap:      addrMap,
		transport:    transport,
		certFile:     certFile,
		keyFile:      keyFile,
	}
}

func (m *MidModule) Start(addr string) error {
	if m.transport == "tls" {
		cert, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
		if err != nil {
			return err
		}
		config := &tls.Config{Certificates: []tls.Certificate{cert}}
		listener, err := tls.Listen("tcp", addr, config)
		if err != nil {
			return err
		}
		m.listener = listener
		go m.acceptTLS()
	} else {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		m.conn = conn
		go m.listenUDP()
	}
	return nil
}

func (m *MidModule) Stop() {
	if m.conn != nil {
		m.conn.Close()
	}
	if m.listener != nil {
		m.listener.Close()
	}
}

func (m *MidModule) listenUDP() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := m.conn.(*net.UDPConn).ReadFromUDP(buf)
		if err != nil {
			break
		}
		go m.HandlePacket(buf[:n], addr)
	}
}

func (m *MidModule) acceptTLS() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			break
		}
		go m.handleTLS(conn)
	}
}

func (m *MidModule) handleTLS(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 65536)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		m.HandlePacket(buf[:n], conn.RemoteAddr())
	}
}

func (m *MidModule) HandlePacket(data []byte, clientAddr net.Addr) error {
	pkt, err := UnmarshalPacket(data)
	if err != nil {
		return err
	}
	if pkt.HopIndex < 1 || pkt.HopIndex >= pkt.TotalHops-1 {
		return errors.New("invalid hop for mid")
	}
	sess, err := m.sessionStore.Get(pkt.SessionID)
	if err != nil {
		return err
	}
	plain, err := DecryptLayer(sess.Keys[pkt.HopIndex], pkt.Payload)
	if err != nil {
		return err
	}
	nextID, ok := pkt.NextHopID()
	if !ok {
		return errors.New("no next hop")
	}
	nextAddr, ok := m.addrMap[nextID]
	if !ok {
		return errors.New("next hop address unknown")
	}
	newPkt := &Packet{
		Version:        pkt.Version,
		HopIndex:       pkt.HopIndex + 1,
		TotalHops:      pkt.TotalHops,
		Flags:          pkt.Flags,
		SessionID:      pkt.SessionID,
		RouteVector:    pkt.RouteVector,
		FragmentID:     pkt.FragmentID,
		TotalFragments: pkt.TotalFragments,
		PayloadLen:     uint16(len(plain)),
		Payload:        plain,
	}
	conn, err := net.Dial("udp", nextAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(newPkt.Marshal())
	return err
}

// ---------- ExitModule ----------
type ExitModule struct {
	sessionStore  *SessionStore
	targetAddr    string
	fragmentStore map[uint32]map[byte][]byte
	conn          net.Conn
	transport     string
	certFile      string
	keyFile       string
	listener      net.Listener
}

func NewExitModule(store *SessionStore, targetAddr, transport, certFile, keyFile string) *ExitModule {
	return &ExitModule{
		sessionStore:  store,
		targetAddr:    targetAddr,
		fragmentStore: make(map[uint32]map[byte][]byte),
		transport:     transport,
		certFile:      certFile,
		keyFile:       keyFile,
	}
}

func (e *ExitModule) Start(addr string) error {
	if e.transport == "tls" {
		cert, err := tls.LoadX509KeyPair(e.certFile, e.keyFile)
		if err != nil {
			return err
		}
		config := &tls.Config{Certificates: []tls.Certificate{cert}}
		listener, err := tls.Listen("tcp", addr, config)
		if err != nil {
			return err
		}
		e.listener = listener
		go e.acceptTLS()
	} else {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		e.conn = conn
		go e.listenUDP()
	}
	return nil
}

func (e *ExitModule) Stop() {
	if e.conn != nil {
		e.conn.Close()
	}
	if e.listener != nil {
		e.listener.Close()
	}
}

func (e *ExitModule) listenUDP() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := e.conn.(*net.UDPConn).ReadFromUDP(buf)
		if err != nil {
			break
		}
		go e.HandlePacket(buf[:n], addr)
	}
}

func (e *ExitModule) acceptTLS() {
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			break
		}
		go e.handleTLS(conn)
	}
}

func (e *ExitModule) handleTLS(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 65536)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		e.HandlePacket(buf[:n], conn.RemoteAddr())
	}
}

func (e *ExitModule) HandlePacket(data []byte, clientAddr net.Addr) error {
	pkt, err := UnmarshalPacket(data)
	if err != nil {
		return err
	}
	if pkt.HopIndex != pkt.TotalHops-1 {
		return errors.New("not exit hop")
	}
	sess, err := e.sessionStore.Get(pkt.SessionID)
	if err != nil {
		return err
	}
	plain, err := DecryptLayer(sess.Keys[pkt.HopIndex], pkt.Payload)
	if err != nil {
		return err
	}
	if pkt.Flags&FlagFragment != 0 {
		if e.fragmentStore[pkt.SessionID] == nil {
			e.fragmentStore[pkt.SessionID] = make(map[byte][]byte)
		}
		e.fragmentStore[pkt.SessionID][pkt.FragmentID] = plain
		if len(e.fragmentStore[pkt.SessionID]) == int(pkt.TotalFragments) {
			parts := make([][]byte, pkt.TotalFragments)
			for i := byte(0); i < pkt.TotalFragments; i++ {
				parts[i] = e.fragmentStore[pkt.SessionID][i]
			}
			full, err := CombineData(parts)
			if err == nil {
				e.sendToTarget(full)
			}
			delete(e.fragmentStore, pkt.SessionID)
		}
	} else {
		e.sendToTarget(plain)
	}
	return nil
}

func (e *ExitModule) sendToTarget(data []byte) {
	conn, err := net.Dial("tcp", e.targetAddr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write(data)
}

// ---------- Balancer ----------
type Balancer struct {
	mu           sync.RWMutex
	nodeID       uint32
	registry     *Registry
	maxLoad      float64
	activateFunc func(role string) error
}

func NewBalancer(nodeID uint32, reg *Registry, maxLoad float64, activate func(string) error) *Balancer {
	b := &Balancer{
		nodeID:       nodeID,
		registry:     reg,
		maxLoad:      maxLoad,
		activateFunc: activate,
	}
	go b.loop()
	return b
}

func (b *Balancer) loop() {
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		// Заглушка
	}
}

// ---------- UniversalNode ----------
type UniversalNode struct {
	directory.UnimplementedDirectoryServer
	mu           sync.RWMutex
	currentRole  NodeRole
	modules      map[NodeRole]Module
	activeModule Module
	sessionStore *SessionStore
	nodeID       uint32
	registry     *Registry
	gossip       *Gossip
	grpcServer   *grpc.Server
	grpcAddr     string
	udpPort      string
	addrMap      map[uint32]string
	balancer     *Balancer
	maxLoad      float64
	transport    string
	certFile     string
	keyFile      string
	initialRole  string
}

func NewUniversalNode(cfg *Config) *UniversalNode {
	if cfg.NodeID == 0 {
		cfg.NodeID = uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	}
	store := NewSessionStore()
	reg := NewRegistry()
	addrMap := make(map[uint32]string)

	entryMod := NewEntryModule(store, addrMap, cfg.Transport, cfg.CertFile, cfg.KeyFile)
	midMod := NewMidModule(store, addrMap, cfg.Transport, cfg.CertFile, cfg.KeyFile)
	exitMod := NewExitModule(store, cfg.ExitAddr, cfg.Transport, cfg.CertFile, cfg.KeyFile)

	grpcSrv := grpc.NewServer()
	node := &UniversalNode{
		currentRole:  RoleIdle,
		modules:      map[NodeRole]Module{RoleEntry: entryMod, RoleMid: midMod, RoleExit: exitMod},
		sessionStore: store,
		nodeID:       cfg.NodeID,
		registry:     reg,
		grpcServer:   grpcSrv,
		grpcAddr:     cfg.GrpcListen,
		udpPort:      cfg.Listen,
		addrMap:      addrMap,
		maxLoad:      cfg.MaxLoad,
		transport:    cfg.Transport,
		certFile:     cfg.CertFile,
		keyFile:      cfg.KeyFile,
		initialRole:  cfg.InitialRole,
	}
	directory.RegisterDirectoryServer(grpcSrv, node)
	return node
}

func (n *UniversalNode) Start() error {
	n.registry.AddOrUpdate(&NodeInfo{
		ID:       n.nodeID,
		Address:  n.udpPort,
		NodeType: "idle",
		Active:   true,
		Country:  "US",
		City:     "NY",
		LastSeen: time.Now(),
	})

	go func() {
		lis, err := net.Listen("tcp", n.grpcAddr)
		if err != nil {
			log.Fatalf("[Node %d] gRPC listen: %v", n.nodeID, err)
		}
		log.Printf("[Node %d] gRPC on %s", n.nodeID, n.grpcAddr)
		n.grpcServer.Serve(lis)
	}()

	n.gossip = NewGossip(n.nodeID, n.registry, []string{})

	if n.initialRole != "" {
		n.ActivateRole(NodeRole(n.initialRole))
	} else {
		n.ActivateRole(RoleEntry)
	}

	n.balancer = NewBalancer(n.nodeID, n.registry, n.maxLoad, func(role string) error {
		return n.ActivateRole(NodeRole(role))
	})

	go n.heartbeatLoop()
	go n.updateAddrMapLoop()
	return nil
}

func (n *UniversalNode) heartbeatLoop() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		n.registry.AddOrUpdate(&NodeInfo{
			ID:       n.nodeID,
			NodeType: string(n.currentRole),
			Active:   true,
			LastSeen: time.Now(),
			Load:     0.5,
		})
	}
}

func (n *UniversalNode) updateAddrMapLoop() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		nodes := n.registry.GetAllNodes()
		n.mu.Lock()
		for _, node := range nodes {
			n.addrMap[node.ID] = node.Address
		}
		n.mu.Unlock()
	}
}

// gRPC методы
func (n *UniversalNode) RegisterNode(ctx context.Context, req *directory.RegisterRequest) (*directory.RegisterResponse, error) {
	var x25519 [32]byte
	copy(x25519[:], req.X25519Pub)
	n.registry.AddOrUpdate(&NodeInfo{
		ID:        req.NodeId,
		Address:   req.Address,
		PublicKey: req.PublicKey,
		X25519Pub: x25519,
		NodeType:  "idle",
		Active:    true,
		Country:   req.Country,
		City:      req.City,
		LastSeen:  time.Now(),
	})
	return &directory.RegisterResponse{Success: true}, nil
}

func (n *UniversalNode) Heartbeat(ctx context.Context, req *directory.HeartbeatRequest) (*directory.HeartbeatResponse, error) {
	if info, ok := n.registry.GetNode(req.NodeId); ok {
		info.Load = req.Load
		info.LastSeen = time.Now()
		info.Active = true
		n.registry.AddOrUpdate(info)
	}
	return &directory.HeartbeatResponse{Success: true}, nil
}

func (n *UniversalNode) GetNodes(ctx context.Context, req *directory.GetNodesRequest) (*directory.GetNodesResponse, error) {
	nodes := n.registry.GetNodes(req.Role, req.Country)
	pb := make([]*directory.NodeInfo, len(nodes))
	for i, node := range nodes {
		pb[i] = node.ToProto()
	}
	return &directory.GetNodesResponse{Nodes: pb}, nil
}

func (n *UniversalNode) SyncRegistry(ctx context.Context, req *directory.SyncRequest) (*directory.SyncResponse, error) {
	nodes := n.registry.GetAllNodes()
	pb := make([]*directory.NodeInfo, len(nodes))
	for i, node := range nodes {
		pb[i] = node.ToProto()
	}
	return &directory.SyncResponse{Nodes: pb}, nil
}

func (n *UniversalNode) ActivateRole(role NodeRole) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.activeModule != nil {
		n.activeModule.Stop()
	}
	mod, ok := n.modules[role]
	if !ok {
		return errors.New("unknown role")
	}
	if err := mod.Start(n.udpPort); err != nil {
		return err
	}
	n.activeModule = mod
	n.currentRole = role
	n.registry.AddOrUpdate(&NodeInfo{
		ID:       n.nodeID,
		NodeType: string(role),
		Active:   true,
		LastSeen: time.Now(),
	})
	return nil
}
