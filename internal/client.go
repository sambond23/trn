package internal

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"time"
	"trn/proto/directory"

	"google.golang.org/grpc"
)

type TRNClient struct {
	registry     *Registry
	bootNodes    []string
	selectedExit uint32
	session      *Session
	transport    string
	certFile     string
	keyFile      string
}

func NewTRNClient(boot []string, transport, certFile, keyFile string) *TRNClient {
	return &TRNClient{
		bootNodes: boot,
		registry:  NewRegistry(),
		transport: transport,
		certFile:  certFile,
		keyFile:   keyFile,
	}
}

func (c *TRNClient) Connect() error {
	if len(c.bootNodes) == 0 {
		return fmt.Errorf("no boot nodes")
	}
	addr := c.bootNodes[rand.Intn(len(c.bootNodes))]
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(5*time.Second))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := directory.NewDirectoryClient(conn)
	resp, err := client.SyncRegistry(context.Background(), &directory.SyncRequest{NodeId: 0})
	if err != nil {
		return err
	}
	for _, pb := range resp.Nodes {
		c.registry.AddOrUpdate(FromProto(pb))
	}
	log.Printf("Client: loaded %d nodes", len(resp.Nodes))
	return nil
}

func (c *TRNClient) SelectExit(country string) (uint32, error) {
	nodes := c.registry.GetNodes("exit", country)
	if len(nodes) == 0 {
		return 0, fmt.Errorf("no exit in %s", country)
	}
	node := nodes[rand.Intn(len(nodes))]
	c.selectedExit = node.ID
	log.Printf("Selected exit %d in %s", node.ID, country)
	return node.ID, nil
}

func (c *TRNClient) BuildRoute() ([]uint32, error) {
	entries := c.registry.GetNodes("entry", "")
	mids := c.registry.GetNodes("mid", "")
	if len(entries) == 0 || len(mids) == 0 {
		return nil, fmt.Errorf("not enough nodes")
	}
	exit, ok := c.registry.GetNode(c.selectedExit)
	if !ok {
		return nil, fmt.Errorf("exit not found")
	}
	route := []uint32{
		entries[rand.Intn(len(entries))].ID,
		mids[rand.Intn(len(mids))].ID,
		exit.ID,
	}
	return route, nil
}

func (c *TRNClient) SendData(data []byte) error {
	if c.session == nil {
		route, err := c.BuildRoute()
		if err != nil {
			return err
		}
		// сбор ключей
		nodeX25519Pub := make(map[uint32][32]byte)
		nodeEdPub := make(map[uint32]ed25519.PublicKey)
		for _, id := range route {
			node, ok := c.registry.GetNode(id)
			if !ok {
				return fmt.Errorf("node %d not found", id)
			}
			nodeEdPub[id] = node.PublicKey
			nodeX25519Pub[id] = node.X25519Pub
		}
		xPriv, _, _ := GenerateX25519Keypair()
		_, edPriv, _ := GenerateEd25519Keypair()
		entry, _ := c.registry.GetNode(route[0])
		sess, err := PerformHandshake(entry.Address, route, nodeEdPub, nodeX25519Pub, edPriv, xPriv)
		if err != nil {
			return err
		}
		c.session = sess
	}

	// шифрование
	encrypted := data
	for i := len(c.session.RouteNodes) - 1; i >= 0; i-- {
		var err error
		encrypted, err = EncryptLayer(c.session.Keys[i], encrypted)
		if err != nil {
			return err
		}
	}

	// фрагментация при необходимости
	if len(encrypted) > 1400 {
		frags, err := SplitData(encrypted, 3, 2)
		if err != nil {
			return err
		}
		for i, frag := range frags {
			pkt := c.makePacket(byte(i), byte(len(frags)), frag)
			if err := c.sendPacket(pkt); err != nil {
				log.Printf("send fragment error: %v", err)
			}
		}
	} else {
		pkt := c.makePacket(0, 1, encrypted)
		return c.sendPacket(pkt)
	}
	return nil
}

func (c *TRNClient) makePacket(fragID, total byte, payload []byte) *Packet {
	route := c.session.RouteNodes
	routeBytes := make([]byte, len(route)*4)
	for i, id := range route {
		binary.BigEndian.PutUint32(routeBytes[i*4:], id)
	}
	return &Packet{
		Version:        Version,
		HopIndex:       0,
		TotalHops:      byte(len(route)),
		Flags:          FlagFragment,
		SessionID:      c.session.ID,
		RouteVector:    routeBytes,
		FragmentID:     fragID,
		TotalFragments: total,
		PayloadLen:     uint16(len(payload)),
		Payload:        payload,
	}
}

func (c *TRNClient) sendPacket(pkt *Packet) error {
	entry, _ := c.registry.GetNode(c.session.RouteNodes[0])
	addr := entry.Address
	var conn net.Conn
	var err error
	if c.transport == "tls" {
		conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.Dial("udp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(pkt.Marshal())
	return err
}

func (c *TRNClient) Run() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("TRN Client ready. Enter message (or 'quit'):")
	for scanner.Scan() {
		line := scanner.Text()
		if line == "quit" {
			break
		}
		if err := c.SendData([]byte(line)); err != nil {
			log.Printf("send error: %v", err)
		}
	}
}
