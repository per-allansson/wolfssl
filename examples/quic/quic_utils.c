#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h> // System headers next
#include <string.h>
#include <errno.h>
#include <netdb.h>

#include "quic_utils.h" // Local project headers, which includes wolfssl/ssl.h etc.

// Callback implementations

int quic_set_encryption_secrets_cb(WOLFSSL* ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                   const uint8_t* read_secret,
                                   const uint8_t* write_secret,
                                   size_t secret_len)
{
    (void)ssl;
    fprintf(stderr, "QUIC_CB: Set encryption secrets for level %d, len %zu. Read:%s Write:%s\n",
            level, secret_len, read_secret ? "Yes" : "No", write_secret ? "Yes" : "No");
    // In a real application, these secrets might be stored or used to configure
    // external crypto hardware if not using wolfSSL's internal crypto.
    // For this example, logging is sufficient.
    return 1; // Success
}

int quic_add_handshake_data_cb(WOLFSSL* ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                               const uint8_t* data, size_t len)
{
    QuicSocketContext* sockCtx = (QuicSocketContext*)wolfSSL_get_app_data(ssl);
    ssize_t sent_len;

    if (sockCtx == NULL || sockCtx->sock_fd < 0) {
        fprintf(stderr, "QUIC_CB_ERR: Add handshake data - invalid socket context or FD.\n");
        return 0; // Failure
    }

    fprintf(stderr, "QUIC_CB: Add handshake data, level %d, len %zu. Sending to peer.\n",
            level, len);

    // For a client, the peer_addr might not be set until the first send.
    // However, wolfSSL_connect is usually called after setting the peer with wolfSSL_dtls_set_peer.
    // For QUIC, this peer information should be part of QuicSocketContext.
    // The client will set this up before calling wolfSSL_connect.
    // The server will get peer_addr from the first received packet.

    if (sockCtx->peer_addr_len == 0) {
        if (sockCtx->is_server) {
            fprintf(stderr, "QUIC_CB_ERR: Server's peer_addr not set. Cannot send handshake data.\n");
            // This should not happen if the server has received data and set peer_addr.
            return 0;
        } else {
            // For client, peer_addr should have been set by create_udp_socket and stored.
            // If it's still not set, it's an issue.
             fprintf(stderr, "QUIC_CB_ERR: Client's peer_addr not set. Cannot send handshake data.\n");
            return 0;
        }
    }

    sent_len = sendto(sockCtx->sock_fd, data, len, 0,
                      (struct sockaddr*)&sockCtx->peer_addr, sockCtx->peer_addr_len);

    if (sent_len < 0) {
        fprintf(stderr, "QUIC_CB_ERR: sendto failed: %s\n", strerror(errno));
        return 0; // Failure
    }
    if ((size_t)sent_len != len) {
        fprintf(stderr, "QUIC_CB_WARN: sendto sent %zd bytes, expected %zu\n",
                sent_len, len);
        // Partial send is not typical for UDP with sendto, but check anyway.
        return 0; // Indicate failure for simplicity
    }

    fprintf(stderr, "QUIC_CB: Successfully sent %zd bytes of handshake data.\n", sent_len);
    return 1; // Success
}

int quic_flush_flight_cb(WOLFSSL* ssl)
{
    (void)ssl;
    // For UDP, sendto typically sends immediately.
    // This callback might be used for more complex scenarios, e.g., with DTLS batching
    // or if the underlying transport does its own batching.
    fprintf(stderr, "QUIC_CB: Flush flight called.\n");
    return 1; // Success
}

int quic_send_alert_cb(WOLFSSL* ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                       uint8_t alert)
{
    (void)ssl;
    // As discussed, sending alerts is complex. wolfSSL will typically embed alerts
    // into the crypto stream which is then passed to quic_add_handshake_data_cb.
    // This callback is more of a notification.
    fprintf(stderr, "QUIC_CB: Send alert, level %d, alert_code %u.\n",
            level, alert);
    // If direct sending of an alert packet was required here, it would involve:
    // 1. Getting QuicSocketContext from wolfSSL_get_app_data(ssl).
    // 2. Formatting a minimal QUIC packet containing the alert.
    // 3. Using sendto() to send it.
    // For now, we assume wolfSSL handles formatting alerts into data given to
    // quic_add_handshake_data_cb.
    return 1; // Success
}

// Helper function to initialize the WOLFSSL_QUIC_METHOD structure
void init_quic_method(WOLFSSL_QUIC_METHOD* method)
{
    if (method != NULL) {
        method->set_encryption_secrets = quic_set_encryption_secrets_cb;
        method->add_handshake_data     = quic_add_handshake_data_cb;
        method->flush_flight           = quic_flush_flight_cb;
        method->send_alert             = quic_send_alert_cb;
    }
}

// Helper function to create and configure a UDP socket
int create_udp_socket(const char* host, int port, int is_server,
                      struct sockaddr_storage* addr_out, socklen_t* addr_len_out)
{
    int sockfd = -1;
    struct addrinfo hints, *servinfo = NULL, *p = NULL;
    char port_str[16];
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_DGRAM;
    if (is_server) {
        hints.ai_flags = AI_PASSIVE; // For wildcard IP address if host is NULL
    }

    snprintf(port_str, sizeof(port_str), "%d", port);

    if ((rv = getaddrinfo(host, port_str, &hints, &servinfo)) != 0) {
        fprintf(stderr, "SOCKET_ERR: getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // Loop through all the results and try to create/bind socket
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("SOCKET_ERR: socket");
            continue;
        }

        if (is_server) {
            // Server: Bind to the address
            if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                close(sockfd);
                perror("SOCKET_ERR: bind");
                sockfd = -1; // Ensure sockfd is -1 if bind fails
                continue;
            }
            fprintf(stderr, "SOCKET: Server socket bound to %s port %d\n",
                    host ? host : "any", port);
        } else {
            // Client: No bind needed here, connect() or sendto() will use an ephemeral port.
            // We store the server's address for sendto.
            fprintf(stderr, "SOCKET: Client socket created, server target %s port %d\n",
                    host, port);
        }

        // Successfully created/bound socket
        if (addr_out != NULL && addr_len_out != NULL) {
            memcpy(addr_out, p->ai_addr, p->ai_addrlen);
            *addr_len_out = p->ai_addrlen;
        }
        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL && sockfd == -1) { // sockfd check added for clarity
        if (is_server)
            fprintf(stderr, "SOCKET_ERR: Server failed to bind socket.\n");
        else
            fprintf(stderr, "SOCKET_ERR: Client failed to create socket.\n");
        return -1;
    }

    // For client, if host was specified, addr_out now contains the server's address.
    // For server, addr_out contains the address it bound to.

    return sockfd;
}
