package client

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	mrand "math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	coordinatorv1 "github.com/fn0rd-io/protobuf/coordinator/v1"
	"github.com/fn0rd-io/protobuf/coordinator/v1/coordinatorconnect"
	"github.com/fn0rd-io/scanner/pkg/common"
	_ "github.com/fn0rd-io/scanner/pkg/nmap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	baseBackoff       = 1 * time.Second
	maxBackoff        = 60 * time.Second
	reconnectWaitTime = 1 * time.Second
)

// Error constants
var (
	ErrNoWorkers        = errors.New("must specify at least one worker")
	ErrNoPrivateKey     = errors.New("must provide a private key")
	ErrInvalidPublicKey = errors.New("public key is not an Ed25519 key")
	ErrTaskExpired      = errors.New("task expired before processing")
	ErrNotConnected     = errors.New("not connected to coordinator")
)

// NewClient creates a new coordinator client
func NewClient(config Config) (*Client, error) {
	if config.Workers == 0 {
		return nil, ErrNoWorkers
	}

	if config.PrivateKey == nil {
		return nil, ErrNoPrivateKey
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		config:      config,
		ctx:         ctx,
		cancel:      cancel,
		taskCh:      make(chan *coordinatorv1.TargetResponse, config.Workers),
		reconnectCh: make(chan struct{}, 1), // Buffer of 1 to prevent blocking
		stateMu:     sync.Mutex{},
	}

	totalWorkers.Set(float64(config.Workers))

	return client, nil
}

// Start begins the client's operation by connecting to the coordinator
// and starting worker goroutines
func (c *Client) Start() error {
	c.InitMetrics()

	// Start the workers
	c.startWorkers()

	// Start goroutines for connection management and message handling
	go c.connectionManager()
	go c.receiveMessages()

	// Trigger initial connection
	c.reconnectCh <- struct{}{}

	return nil
}

// Stop gracefully shuts down the client
func (c *Client) Stop() {
	log.Println("Shutting down scanner client...")
	c.cancel()
	c.activeWorkers.Wait()
	log.Println("Scanner client stopped")
}

// startWorkers launches the specified number of worker goroutines
func (c *Client) startWorkers() {
	for i := uint32(0); i < c.config.Workers; i++ {
		c.activeWorkers.Add(1)
		go c.worker(i + 1)
	}
}

// connectionManager handles the connection lifecycle including reconnection logic
func (c *Client) connectionManager() {
	log.Printf("Connection manager started for coordinator at %s", c.config.CoordinatorURL)

	// Create connect client
	client := coordinatorconnect.NewCoordinatorServiceClient(
		http.DefaultClient,
		c.config.CoordinatorURL,
		connect.WithGRPC(),
	)

	pingTimer := time.NewTicker(5 * time.Second)
	defer pingTimer.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-pingTimer.C:
			if err := c.sendPing(); err != nil {
				if errors.Is(err, ErrNotConnected) {
					continue
				}
				log.Printf("Failed to send ping: %v", err)
				streamErrors.Inc()
				c.triggerReconnect(err)
			}
		case <-c.reconnectCh:
			c.stateMu.Lock()
			c.stream = client.Stream(c.ctx)
			c.registered = false
			c.stateMu.Unlock()
			log.Printf("Connection established")
		}
	}
}

// sendPing sends a ping message to the coordinator
func (c *Client) sendPing() error {
	nonce, err := generateNonce(16)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.stream == nil || !c.registered {
		return ErrNotConnected
	}
	stream := c.stream
	return stream.Send(&coordinatorv1.StreamRequest{
		Nonce: nonce,
		Request: &coordinatorv1.StreamRequest_Ping{
			Ping: &coordinatorv1.PingRequest{
				Timestamp: timestamppb.Now(),
			},
		},
	})
}

// calculateBackoff determines the next backoff period with jitter
func calculateBackoff(base time.Duration, attempt uint8, max time.Duration) time.Duration {
	backoff := time.Duration(float64(base) * math.Pow(1.5, float64(attempt)))
	if backoff > max {
		backoff = max
	}

	// Add jitter (±20%)
	jitter := time.Duration(mrand.Float64()*0.4*float64(backoff) - 0.2*float64(backoff))

	log.Printf("Calculated backoff: %v + %v", backoff, jitter)
	return backoff + jitter
}

// register sends registration information to the coordinator
func (c *Client) register() error {
	// Extract public key from private key
	ed25519PubKey, ok := c.config.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return ErrInvalidPublicKey
	}

	// Use the raw bytes directly - this will be exactly 32 bytes
	pubKeyBytes := []byte(ed25519PubKey)

	// Generate nonce
	nonce, err := generateNonce(16)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Determine capabilities
	capabilities := c.determineCapabilities()

	// Create registration request
	req := &coordinatorv1.StreamRequest{
		Nonce: nonce,
		Request: &coordinatorv1.StreamRequest_Register{
			Register: &coordinatorv1.RegisterRequest{
				PublicKey:    pubKeyBytes,
				Workers:      c.config.Workers,
				Capabilities: capabilities,
			},
		},
	}

	// Sign the request
	if err := c.signRequest(req, nonce, c.config.Workers); err != nil {
		return err
	}

	// Send registration
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.stream == nil {
		return ErrNotConnected
	}
	stream := c.stream

	if err := stream.Send(req); err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	log.Printf("Registration with %d workers sent successfully", c.config.Workers)
	c.registered = true
	return nil
}

// determineCapabilities checks what capabilities this scanner supports
func (c *Client) determineCapabilities() []coordinatorv1.Capability {
	capabilities := []coordinatorv1.Capability{}

	// Check if Nmap scanner is available
	n, err := common.GetScanner("nmap").New(context.Background(), "127.0.0.1", "", true)
	if err != nil {
		log.Printf("Cannot create Nmap scanner: %v", err)
	} else {
		capabilities = append(capabilities, coordinatorv1.Capability_CAPABILITY_NMAP)
		if _, err := n.Run(); err == nil {
			c.config.UDP = true
			capabilities = append(capabilities, coordinatorv1.Capability_CAPABILITY_NMAP_FULL)
		} else {
			log.Printf("Limiting Capabilities to TCP-Only: %v", err)
		}
	}

	return capabilities
}

// generateNonce creates a cryptographically secure random nonce
func generateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	_, err := rand.Read(nonce)
	return nonce, err
}

// signRequest signs a request with the client's private key
func (c *Client) signRequest(req *coordinatorv1.StreamRequest, nonce []byte, workerCount uint32) error {
	// Prepare data to sign: nonce + worker count as bytes
	workerBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(workerBytes, workerCount)
	dataToSign := append(nonce, workerBytes...)

	// Sign the raw message (Ed25519 does its own hashing internally)
	signature, err := c.config.PrivateKey.Sign(rand.Reader, dataToSign, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	req.Signature = signature
	return nil
}

// receiveMessages handles incoming messages from the coordinator
func (c *Client) receiveMessages() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			// Get stream safely
			c.stateMu.Lock()
			stream := c.stream
			reg := c.registered
			c.stateMu.Unlock()

			// Handle nil stream case
			if stream == nil {
				log.Printf("Stream is nil, waiting for connection...")
				time.Sleep(reconnectWaitTime)
				continue
			}

			if !reg {
				log.Printf("Not registered, attempting to register...")
				if err := c.register(); err != nil {
					log.Printf("Failed to register: %v", err)
					c.triggerReconnect(err)
					continue
				}
			}

			// Try to receive a message
			resp, err := stream.Receive()
			if err != nil {
				log.Printf("Error receiving message: %v", err)
				streamErrors.Inc()
				c.triggerReconnect(err)
				continue
			}

			// Reset attempt counter on successful receive
			if c.attempt > 0 {
				c.attempt = 0
			}

			// Process the response
			switch {
			case resp.GetTarget() != nil:
				target := resp.GetTarget()
				c.taskCh <- target
				tasksAssigned.Inc()
			case resp.GetPing() != nil:
				// No need to do anything for pings
			default:
				log.Printf("Received unknown response type")
			}
		}
	}
}

// triggerReconnect signals that a reconnection is needed
func (c *Client) triggerReconnect(err error) {
	c.stateMu.Lock()
	c.attempt++
	c.stream = nil
	c.registered = false
	c.stateMu.Unlock()
	log.Printf("Reconnection triggered: %v", err)
	time.Sleep(calculateBackoff(baseBackoff, c.attempt, maxBackoff))
	select {
	case c.reconnectCh <- struct{}{}:
		// Signal sent successfully
	default:
		// Channel is full (reconnection already triggered)
	}
}

// worker processes tasks received from the coordinator
func (c *Client) worker(id uint32) {
	defer c.activeWorkers.Done()
	log.Printf("Worker %d started", id)

	for {
		select {
		case <-c.ctx.Done():
			log.Printf("Worker %d shutting down", id)
			return
		case task := <-c.taskCh:
			c.processTask(id, task)
		}
	}
}

// processTask handles a single scanning task
func (c *Client) processTask(id uint32, task *coordinatorv1.TargetResponse) {
	target := task.Target
	deadline := task.Deadline.AsTime()

	// Calculate time remaining until deadline
	if time.Until(deadline) < 0 {
		log.Printf("Worker %d: task already expired, skipping", id)
		c.submitResult(Result{
			Target: target,
			Error:  ErrTaskExpired,
		})
		return
	}

	// Create context with deadline
	ctx, cancel := context.WithDeadline(c.ctx, deadline)
	defer cancel()

	// Run the scan
	result, err := c.runScan(ctx, id, target)
	c.submitResult(Result{
		Target: target,
		Data:   result,
		Error:  err,
	})
}

// runScan executes an Nmap scan against the target
func (c *Client) runScan(ctx context.Context, id uint32, target []byte) ([]byte, error) {
	n, err := common.GetScanner("nmap").New(ctx, net.IP(target).String(), c.config.Interface, c.config.UDP)
	if err != nil {
		log.Printf("Worker %d: failed to create Nmap scanner: %v", id, err)
		return nil, fmt.Errorf("scanner initialization failed: %w", err)
	}

	result, err := n.Run()
	if err != nil {
		log.Printf("Worker %d: task failed: %v", id, err)
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	return result, nil
}

// submitResult sends a task result to the coordinator
func (c *Client) submitResult(result Result) {
	if result.Error != nil {
		log.Printf("Task error: %v", result.Error)
		tasksFailed.Inc()
	}

	// Generate nonce
	nonce, err := generateNonce(16)
	if err != nil {
		log.Printf("Failed to generate nonce: %v", err)
		c.triggerReconnect(err)
		return
	}

	// Create submit request
	req := &coordinatorv1.StreamRequest{
		Nonce: nonce,
		Request: &coordinatorv1.StreamRequest_Submit{
			Submit: &coordinatorv1.SubmitRequest{
				Result: result.Data,
			},
		},
	}

	// Prepare data to sign: nonce + result data
	dataToSign := append(nonce, result.Data...)

	// Sign the raw message (Ed25519 does its own hashing internally)
	signature, err := c.config.PrivateKey.Sign(rand.Reader, dataToSign, crypto.Hash(0))
	if err != nil {
		log.Printf("Failed to sign request: %v", err)
		c.triggerReconnect(err)
		return
	}

	req.Signature = signature

	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.stream == nil || !c.registered {
		log.Printf("Cannot submit result: not connected")
		return
	}
	stream := c.stream

	// Send result
	if err := stream.Send(req); err != nil {
		log.Printf("Failed to send result: %v", err)
		streamErrors.Inc()
		c.triggerReconnect(err)
		return
	}

	tasksCompleted.Inc()
}
