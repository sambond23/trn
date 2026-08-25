package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// ---------- Packet ----------
const (
	Version = 0x03
	MaxHops = 64
)

type Flags byte

const (
	FlagFragment Flags = 1 << 0
	FlagLast     Flags = 1 << 1
)

type Packet struct {
	Version        byte
	HopIndex       byte
	TotalHops      byte
	Flags          Flags
	SessionID      uint32
	RouteVector    []byte // uint32 IDs, length = TotalHops*4
	FragmentID     byte
	TotalFragments byte
	PayloadLen     uint16
	Payload        []byte
}

func (p *Packet) Marshal() []byte {
	headerLen := 16
	routeLen := int(p.TotalHops) * 4
	buf := make([]byte, headerLen+routeLen+len(p.Payload))
	buf[0] = p.Version
	buf[1] = p.HopIndex
	buf[2] = p.TotalHops
	buf[3] = byte(p.Flags)
	binary.BigEndian.PutUint32(buf[4:8], p.SessionID)
	buf[8] = p.FragmentID
	buf[9] = p.TotalFragments
	binary.BigEndian.PutUint16(buf[10:12], p.PayloadLen)
	copy(buf[16:16+routeLen], p.RouteVector)
	copy(buf[16+routeLen:], p.Payload)
	return buf
}

func UnmarshalPacket(data []byte) (*Packet, error) {
	if len(data) < 16 {
		return nil, io.ErrShortBuffer
	}
	p := &Packet{
		Version:        data[0],
		HopIndex:       data[1],
		TotalHops:      data[2],
		Flags:          Flags(data[3]),
		SessionID:      binary.BigEndian.Uint32(data[4:8]),
		FragmentID:     data[8],
		TotalFragments: data[9],
		PayloadLen:     binary.BigEndian.Uint16(data[10:12]),
	}
	routeLen := int(p.TotalHops) * 4
	if len(data) < 16+routeLen+int(p.PayloadLen) {
		return nil, io.ErrShortBuffer
	}
	p.RouteVector = data[16 : 16+routeLen]
	p.Payload = data[16+routeLen : 16+routeLen+int(p.PayloadLen)]
	return p, nil
}

func (p *Packet) GetCurrentNodeID() uint32 {
	if int(p.HopIndex) >= len(p.RouteVector)/4 {
		return 0
	}
	off := int(p.HopIndex) * 4
	return binary.BigEndian.Uint32(p.RouteVector[off : off+4])
}

func (p *Packet) NextHopID() (uint32, bool) {
	if p.HopIndex+1 >= p.TotalHops {
		return 0, false
	}
	off := int(p.HopIndex+1) * 4
	return binary.BigEndian.Uint32(p.RouteVector[off : off+4]), true
}

// ---------- Crypto ----------
func GenerateX25519Keypair() (priv, pub [32]byte, err error) {
	if _, err := rand.Read(priv[:]); err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv, pub, nil
}

func SharedSecret(priv, pub [32]byte) [32]byte {
	var sec [32]byte
	curve25519.ScalarMult(&sec, &priv, &pub)
	return sec
}

func EncryptLayer(key []byte, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func DecryptLayer(key []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, io.ErrShortBuffer
	}
	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aead.Open(nil, nonce, data, nil)
}

// GenerateEd25519Keypair возвращает (public, private, error) в правильном порядке
func GenerateEd25519Keypair() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	return ed25519.GenerateKey(rand.Reader)
}

func Sign(priv ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(priv, data)
}

func Verify(pub ed25519.PublicKey, data, sig []byte) bool {
	return ed25519.Verify(pub, data, sig)
}

// ---------- Встроенная реализация Shamir (без внешних зависимостей) ----------
const prime = 257

func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 1)
	for {
		if _, err := rand.Read(b); err == nil {
			v := int(b[0])
			if v < max {
				return v
			}
		}
	}
}

func splitData(data []byte, n, k byte) ([][]byte, error) {
	if n < 2 || k < 2 || k > n {
		return nil, errors.New("invalid n or k")
	}
	parts := make([][]byte, n)
	for i := range parts {
		parts[i] = make([]byte, len(data))
	}

	for idx, b := range data {
		coeff := make([]int, k)
		coeff[0] = int(b)
		for i := 1; i < int(k); i++ {
			coeff[i] = randInt(prime)
		}
		for x := byte(1); x <= n; x++ {
			val := 0
			for i := 0; i < int(k); i++ {
				pow := 1
				for j := 0; j < i; j++ {
					pow = (pow * int(x)) % prime
				}
				val = (val + coeff[i]*pow) % prime
			}
			parts[x-1][idx] = byte(val)
		}
	}
	return parts, nil
}

func combineData(parts [][]byte) ([]byte, error) {
	if len(parts) < 2 {
		return nil, errors.New("need at least 2 parts")
	}
	dataLen := len(parts[0])
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) != dataLen {
			return nil, errors.New("parts length mismatch")
		}
	}
	k := len(parts)
	result := make([]byte, dataLen)

	for idx := 0; idx < dataLen; idx++ {
		xs := make([]int, k)
		ys := make([]int, k)
		for i := 0; i < k; i++ {
			xs[i] = i + 1
			ys[i] = int(parts[i][idx])
		}
		secret := 0
		for i := 0; i < k; i++ {
			num := 1
			den := 1
			for j := 0; j < k; j++ {
				if i == j {
					continue
				}
				num = (num * (0 - xs[j])) % prime
				den = (den * (xs[i] - xs[j])) % prime
			}
			invDen := modInverse(den, prime)
			term := (ys[i] * num % prime) * invDen % prime
			secret = (secret + term) % prime
		}
		if secret < 0 {
			secret += prime
		}
		result[idx] = byte(secret)
	}
	return result, nil
}

func modInverse(a, m int) int {
	if a < 0 {
		a = a%m + m
	}
	t, newt := 0, 1
	r, newr := m, a
	for newr != 0 {
		q := r / newr
		t, newt = newt, t-q*newt
		r, newr = newr, r-q*newr
	}
	if r > 1 {
		return 0
	}
	if t < 0 {
		t += m
	}
	return t
}

// ---------- Экспортируемые обёртки для фрагментации ----------
func SplitData(data []byte, n, k byte) ([][]byte, error) {
	return splitData(data, n, k)
}

func CombineData(parts [][]byte) ([]byte, error) {
	return combineData(parts)
}

// ---------- Handshake ----------
type Session struct {
	ID         uint32
	Keys       [][]byte
	RouteNodes []uint32
	Expires    time.Time
}

type HandshakeInit struct {
	SessionID     uint32
	ClientPub     [32]byte
	EncryptedKeys [][]byte
	ExitNodeID    uint32
	Timestamp     int64
	Signature     []byte
}

type HandshakeAck struct {
	SessionID uint32
	NodeID    uint32
	Timestamp int64
	Signature []byte
}

func PerformHandshake(entryAddr string, route []uint32,
	nodeEdPub map[uint32]ed25519.PublicKey,
	nodeX25519Pub map[uint32][32]byte,
	clientEdPriv ed25519.PrivateKey,
	clientX25519Priv [32]byte) (*Session, error) {

	if len(route) < 3 {
		return nil, errors.New("need at least 3 nodes")
	}
	sid := make([]byte, 4)
	rand.Read(sid)
	sessionID := binary.BigEndian.Uint32(sid)

	n := len(route)
	keys := make([][]byte, n)
	for i := range keys {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
	}

	encKeys := make([][]byte, n)
	for i, id := range route {
		pub, ok := nodeX25519Pub[id]
		if !ok {
			return nil, errors.New("missing X25519 pub")
		}
		sec := SharedSecret(clientX25519Priv, pub)
		enc, err := EncryptLayer(sec[:], keys[i])
		if err != nil {
			return nil, err
		}
		encKeys[i] = enc
	}

	// В реальной реализации здесь отправляется HandshakeInit и проверяются ACK.
	// Для демонстрации мы пропускаем эту часть и сразу возвращаем сессию.

	return &Session{
		ID:         sessionID,
		Keys:       keys,
		RouteNodes: route,
		Expires:    time.Now().Add(1 * time.Hour),
	}, nil
}
