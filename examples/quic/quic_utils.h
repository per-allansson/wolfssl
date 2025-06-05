#ifndef WOLFSSL_QUIC_UTILS_H
#define WOLFSSL_QUIC_UTILS_H

#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> // For close()

// Context for managing the UDP socket and peer information
typedef struct QuicSocketContext {
    int sock_fd;                        // UDP socket file descriptor
    struct sockaddr_storage local_addr; // Local address of the socket
    socklen_t local_addr_len;           // Length of local_addr
    struct sockaddr_storage peer_addr;  // Address of the peer
    socklen_t peer_addr_len;            // Length of peer_addr
    int is_server;                      // Flag to indicate server (1) or client (0) behavior
    int connected;                      // For client, indicates if peer_addr is set (after first send/recv)
} QuicSocketContext;

// QUIC callback function declarations
int quic_set_encryption_secrets_cb(WOLFSSL* ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                   const uint8_t* read_secret,
                                   const uint8_t* write_secret,
                                   size_t secret_len);

int quic_add_handshake_data_cb(WOLFSSL* ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                               const uint8_t* data, size_t len);

int quic_flush_flight_cb(WOLFSSL* ssl);

int quic_send_alert_cb(WOLFSSL* ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                       uint8_t alert);

// Helper function to initialize the WOLFSSL_QUIC_METHOD structure
void init_quic_method(WOLFSSL_QUIC_METHOD* method);

// Helper function to create and configure a UDP socket
// For server: host can be NULL or specific IP, port is listening port.
// For client: host and port are the server's.
// Returns socket FD, or -1 on error.
// Populates addr_out and addr_len_out with the address the socket is bound to (server)
// or the server's resolved address (client).
int create_udp_socket(const char* host, int port, int is_server,
                      struct sockaddr_storage* addr_out, socklen_t* addr_len_out);

#endif // WOLFSSL_QUIC_UTILS_H
