package fragment

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/nadoo/glider/pkg/log"
)

type Config struct {
	Packets  string
	Length   string
	Interval string
}

var C = &Config{}
var fr *Fragment
var FrErr error

func GetFragmentConfig() {
	fr, FrErr = parseFragment()
	if C.Packets != "" && FrErr != nil {
		log.F("parseFragment err: %v", FrErr)
	}
}

func GetFragmentWriter(c net.Conn) *FragmentWriter {
	return &FragmentWriter{
		Fragment: fr,
		Writer:   c,
	}
}

func parseFragment() (*Fragment, error) {
	// https://github.com/XTLS/Xray-core/blob/eba2906d3a31c012c9125940be889d2e75635724/infra/conf/freedom.go#L59
	f := new(Fragment)
	var err, err2 error

	switch strings.ToLower(C.Packets) {
	case "tlshello":
		// TLS Hello Fragmentation (into multiple handshake messages)
		f.PacketsFrom = 0
		f.PacketsTo = 1
	case "":
		// TCP Segmentation (all packets)
		f.PacketsFrom = 0
		f.PacketsTo = 0
	default:
		// TCP Segmentation (range)
		packetsFromTo := strings.Split(C.Packets, "-")
		if len(packetsFromTo) == 2 {
			f.PacketsFrom, err = strconv.ParseUint(packetsFromTo[0], 10, 64)
			f.PacketsTo, err2 = strconv.ParseUint(packetsFromTo[1], 10, 64)
		} else {
			f.PacketsFrom, err = strconv.ParseUint(packetsFromTo[0], 10, 64)
			f.PacketsTo = f.PacketsFrom
		}
		if err != nil {
			return nil, errors.New("invalid PacketsFrom")
		}
		if err2 != nil {
			return nil, errors.New("invalid PacketsTo")
		}
		if f.PacketsFrom > f.PacketsTo {
			f.PacketsFrom, f.PacketsTo = f.PacketsTo, f.PacketsFrom
		}
		if f.PacketsFrom == 0 {
			return nil, errors.New("PacketsFrom can't be 0")
		}
	}

	{
		if C.Length == "" {
			return nil, errors.New("length can't be empty")
		}
		lengthMinMax := strings.Split(C.Length, "-")
		if len(lengthMinMax) == 2 {
			f.LengthMin, err = strconv.ParseUint(lengthMinMax[0], 10, 64)
			f.LengthMax, err2 = strconv.ParseUint(lengthMinMax[1], 10, 64)
		} else {
			f.LengthMin, err = strconv.ParseUint(lengthMinMax[0], 10, 64)
			f.LengthMax = f.LengthMin
		}
		if err != nil {
			return nil, errors.New("invalid LengthMin")
		}
		if err2 != nil {
			return nil, errors.New("invalid LengthMax")
		}
		if f.LengthMin > f.LengthMax {
			f.LengthMin, f.LengthMax = f.LengthMax, f.LengthMin
		}
		if f.LengthMin == 0 {
			return nil, errors.New("LengthMin can't be 0")
		}
	}

	{
		if C.Interval == "" {
			return nil, errors.New("interval can't be empty")
		}
		intervalMinMax := strings.Split(C.Interval, "-")
		if len(intervalMinMax) == 2 {
			f.IntervalMin, err = strconv.ParseUint(intervalMinMax[0], 10, 64)
			f.IntervalMax, err2 = strconv.ParseUint(intervalMinMax[1], 10, 64)
		} else {
			f.IntervalMin, err = strconv.ParseUint(intervalMinMax[0], 10, 64)
			f.IntervalMax = f.IntervalMin
		}
		if err != nil {
			return nil, errors.New("invalid IntervalMin")
		}
		if err2 != nil {
			return nil, errors.New("invalid IntervalMax")
		}
		if f.IntervalMin > f.IntervalMax {
			f.IntervalMin, f.IntervalMax = f.IntervalMax, f.IntervalMin
		}
	}
	return f, nil
}

type Fragment struct {
	PacketsFrom uint64
	PacketsTo   uint64
	LengthMin   uint64
	LengthMax   uint64
	IntervalMin uint64
	IntervalMax uint64
}

type FragmentWriter struct {
	Fragment *Fragment
	Writer   net.Conn
	count    uint64
}

func (f *FragmentWriter) Write(b []byte) (int, error) {
	f.count++

	if f.Fragment.PacketsFrom == 0 && f.Fragment.PacketsTo == 1 {
		if f.count != 1 || len(b) <= 5 || b[0] != 22 {
			return f.Writer.Write(b)
		}
		recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
		if len(b) < recordLen { // maybe already fragmented somehow
			return f.Writer.Write(b)
		}
		data := b[5:recordLen]
		buf := make([]byte, 1024)
		for from := 0; ; {
			to := from + int(randBetween(int64(f.Fragment.LengthMin), int64(f.Fragment.LengthMax)))
			if to > len(data) {
				to = len(data)
			}
			copy(buf[:3], b)
			copy(buf[5:], data[from:to])
			l := to - from
			from = to
			buf[3] = byte(l >> 8)
			buf[4] = byte(l)
			_, err := f.Writer.Write(buf[:5+l])
			time.Sleep(time.Duration(randBetween(int64(f.Fragment.IntervalMin), int64(f.Fragment.IntervalMax))) * time.Millisecond)
			if err != nil {
				return 0, err
			}
			if from == len(data) {
				if len(b) > recordLen {
					n, err := f.Writer.Write(b[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(b), nil
			}
		}
	}

	if f.Fragment.PacketsFrom != 0 && (f.count < f.Fragment.PacketsFrom || f.count > f.Fragment.PacketsTo) {
		return f.Writer.Write(b)
	}
	for from := 0; ; {
		to := from + int(randBetween(int64(f.Fragment.LengthMin), int64(f.Fragment.LengthMax)))
		if to > len(b) {
			to = len(b)
		}
		n, err := f.Writer.Write(b[from:to])
		from += n
		time.Sleep(time.Duration(randBetween(int64(f.Fragment.IntervalMin), int64(f.Fragment.IntervalMax))) * time.Millisecond)
		if err != nil {
			return from, err
		}
		if from >= len(b) {
			return from, nil
		}
	}
}

func (f *FragmentWriter) Read(b []byte) (int, error) {
	return f.Writer.Read(b)
}

func (f *FragmentWriter) Close() error {
	return f.Writer.Close()
}

func (f *FragmentWriter) LocalAddr() net.Addr {
	return f.Writer.LocalAddr()
}

func (f *FragmentWriter) RemoteAddr() net.Addr {
	return f.Writer.RemoteAddr()
}

func (f *FragmentWriter) SetDeadline(t time.Time) error {
	return f.Writer.SetDeadline(t)
}

func (f *FragmentWriter) SetReadDeadline(t time.Time) error {
	return f.Writer.SetReadDeadline(t)
}

func (f *FragmentWriter) SetWriteDeadline(t time.Time) error {
	return f.Writer.SetWriteDeadline(t)
}

// stolen from github.com/xtls/xray-core/transport/internet/reality
func randBetween(left int64, right int64) int64 {
	if left == right {
		return left
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(right-left))
	return left + bigInt.Int64()
}
