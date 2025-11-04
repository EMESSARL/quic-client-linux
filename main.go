package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

const ratio = 1048576

var (
	url          = flag.String("u", "emes.bj", "The server hostname or IP to test against")
	port         = flag.Int("p", 4447, "The UDP QUIC port to use for testing (default 4447)")
	numberStream = flag.Int("n", 30, "The number of streams")
	dataSize     = flag.Int("d", 262144, "The data size (bytes) to send per stream")
	downloadUni  = flag.Bool("uni", false, "Expect unidirectional streams for the download phase (server-initiated)")
	readTO       = flag.Duration("read-timeout", 30*time.Second, "Per-read timeout during download phase")
	idleTO       = flag.Duration("idle-timeout", 45*time.Second, "QUIC connection idle timeout")
)

var mu sync.Mutex

// Generate pseudo-random data
func generatePRData(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := 0; i < l; i++ {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}

// Buffered writer
type bufferedWriteCloser struct {
	*bufio.Writer
	io.Closer
}

func NewBufferedWriteCloser(writer *bufio.Writer, closer io.Closer) io.WriteCloser {
	return &bufferedWriteCloser{Writer: writer, Closer: closer}
}

func (h bufferedWriteCloser) Close() error {
	if err := h.Writer.Flush(); err != nil {
		return err
	}
	return h.Closer.Close()
}

func main() {
	flag.Parse()
	addr := *url + ":" + strconv.Itoa(*port)
	fmt.Println("QUIC client connecting to:", addr)

	// ALPN: 4447 => QUIC brut; 4448 => HTTP/3 (ce client n'envoie pas de requêtes HTTP)
	alpn := []string{"quic-echo-example"}
	if *port == 4448 {
		alpn = []string{"h3", "h3-29", "h3-30", "h3-31"}
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         alpn,
	}

	// QUIC config (compatible quic-go v0.39.x) : pas de KeepAlive ici
	quicC := &quic.Config{
		MaxIncomingStreams: 150,
		MaxIdleTimeout:     *idleTO,
		Tracer: func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
			_ = os.MkdirAll("qlogs", 0755)
			filename := fmt.Sprintf("qlogs/client_%s.qlog", time.Now().Format("2006-01-02_15-04-05"))
			f, _ := os.Create(filename)
			fmt.Printf("Creating client qlog: %s\n", filename)
			w := NewBufferedWriteCloser(bufio.NewWriter(f), f)
			return qlog.NewConnectionTracer(w, p, connID)
		},
	}

	fmt.Println("Starting QUIC test...")
	sess, err := quic.DialAddr(context.Background(), addr, tlsConf, quicC)
	if err != nil {
		fmt.Println("Error connecting to QUIC server:", err)
		return
	}
	fmt.Println("Connected to server:", sess.RemoteAddr())

	// ---------------- Upload Test ----------------
	spin := spinner.New(spinner.CharSets[43], 100*time.Millisecond)
	msg := generatePRData(*dataSize)
	fmt.Printf("Upload test: %d bytes per stream × %d streams\n", *dataSize, *numberStream)

	var w sync.WaitGroup
	spin.Start()
	for i := 0; i < *numberStream; i++ {
		streamUp, err := sess.OpenStreamSync(context.Background())
		if err != nil {
			fmt.Println("Stream creation error:", err)
			continue
		}
		w.Add(1)
		go func(stream quic.Stream) {
			defer w.Done()
			defer stream.Close()

			// deadline plus large et écriture en chunks pour respecter le flow-control
			_ = stream.SetWriteDeadline(time.Now().Add(30 * time.Second))
			remaining := len(msg)
			off := 0
			for remaining > 0 {
				chunk := 64 * 1024
				if remaining < chunk {
					chunk = remaining
				}
				n, err := stream.Write(msg[off : off+chunk])
				if err != nil {
					fmt.Println("Stream write error:", err)
					return
				}
				off += n
				remaining -= n

				// rafraîchit la deadline à chaque chunk
				_ = stream.SetWriteDeadline(time.Now().Add(30 * time.Second))
			}
		}(streamUp)
	}
	w.Wait()
	spin.Stop()
	fmt.Println("Upload complete.")

	// ---------------- Download Test ----------------
	fmt.Println("Download Testing")
	var total int
	var times []time.Duration
	spin.Start()

	expected := *numberStream
	w = sync.WaitGroup{}

	for i := 0; i < expected; i++ {
		w.Add(1)
		go func(ix int) {
			defer w.Done()

			// 1) Essaye d'accepter un flux BIDI avec timeout explicite
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			s, err := sess.AcceptStream(ctx)
			cancel()

			// 2) Fallback UNI si le bidi n'arrive pas à temps
			if err != nil {
				// Essaie un stream unidirectionnel
				ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
				us, uerr := sess.AcceptUniStream(ctx2)
				cancel2()
				if uerr != nil {
					fmt.Println("Stream accept error (bidi+uni):", err, "/", uerr)
					return
				}

				// Lecture du flux uni
				buf := make([]byte, 64*1024)
				t1 := time.Now()
				for {
					// si l'implémentation l'expose, pose une deadline lecture
					type rd interface{ SetReadDeadline(time.Time) error }
					if dd, ok := any(us).(rd); ok {
						_ = dd.SetReadDeadline(time.Now().Add(*readTO))
					}
					n, rerr := us.Read(buf)
					if n > 0 {
						mu.Lock()
						total += n
						mu.Unlock()
					}
					if rerr != nil {
						if rerr == io.EOF {
							break
						}
						// tolère un timeout ponctuel (si exposé)
						type tErr interface{ Timeout() bool }
						if te, ok := rerr.(tErr); ok && te.Timeout() {
							continue
						}
						break
					}
				}
				mu.Lock()
				times = append(times, time.Since(t1))
				mu.Unlock()
				return
			}

			// 3) Lecture du flux bidirectionnel
			defer s.Close()
			buf := make([]byte, 64*1024)
			t1 := time.Now()
			for {
				_ = s.SetReadDeadline(time.Now().Add(*readTO))
				n, rerr := s.Read(buf)
				if n > 0 {
					mu.Lock()
					total += n
					mu.Unlock()
				}
				if rerr != nil {
					if rerr == io.EOF {
						break
					}
					// tolère timeout ponctuel
					type tErr interface{ Timeout() bool }
					if te, ok := rerr.(tErr); ok && te.Timeout() {
						continue
					}
					break
				}
			}
			mu.Lock()
			times = append(times, time.Since(t1))
			mu.Unlock()
		}(i)
	}

	w.Wait()
	spin.Stop()
	fmt.Println("Download Complete")

	if len(times) == 0 || total == 0 {
		fmt.Println("No data received.")
		return
	}

	// Débit moyen
	var totalDur time.Duration
	for _, d := range times {
		totalDur += d
	}
	avgDur := totalDur / time.Duration(len(times))
	bps := float64(total*8) / avgDur.Seconds()
	Mbps := bps / ratio

	fmt.Printf("Received total: %d bytes across %d streams\n", total, len(times))
	fmt.Printf("Download Speed (avg): %.3f Mbps\n", Mbps)
	fmt.Println("Test finished successfully.")
}
