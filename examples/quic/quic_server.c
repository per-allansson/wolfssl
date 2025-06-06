/* Example QUIC server using socket-based I/O */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h> // System headers next
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#include <wolfssl/ssl.h> // Other wolfSSL headers
#include <wolfssl/quic.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "quic_utils.h" // Local project headers

#define SERVER_HOST "0.0.0.0" // Listen on all interfaces
#define SERVER_PORT 11111
#define MAX_RECV_BUF 2048
#define MAX_HANDSHAKE_ITERATIONS 20
#define SERVER_RESPONSE "Hello QUIC Client!"

// Server certificate and key paths
#define CERT_FILE "certs/server-cert.pem"
#define KEY_FILE  "certs/server-key.pem"


int main(int argc, char **argv)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_QUIC_METHOD quic_method_actual;
    QuicSocketContext socket_ctx;
    int ret = 0;
    char err_buffer[WOLFSSL_MAX_ERROR_SZ];
    unsigned char recv_buf[MAX_RECV_BUF]; // Use unsigned char for binary data

    (void)argc;
    (void)argv;

    // Initialize QuicSocketContext
    memset(&socket_ctx, 0, sizeof(QuicSocketContext));
    socket_ctx.sock_fd = -1;
    socket_ctx.is_server = 1;
    socket_ctx.connected = 0; // Server isn't "connected" until it receives from a peer

    fprintf(stderr, "Initializing wolfSSL for QUIC server...\n");
    wolfSSL_Init();

    // Create UDP socket and bind it
    // For the server, create_udp_socket stores the local bound address
    // in socket_ctx.local_addr and socket_ctx.local_addr_len.
    // Peer address will be populated on first recvfrom.
    socket_ctx.sock_fd = create_udp_socket(SERVER_HOST, SERVER_PORT, 1,
                                           &socket_ctx.local_addr,
                                           &socket_ctx.local_addr_len);
    if (socket_ctx.sock_fd < 0) {
        fprintf(stderr, "ERROR: create_udp_socket for server failed\n");
        wolfSSL_Cleanup();
        return -1;
    }

    // Create WOLFSSL_CTX
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "ERROR: wolfSSL_CTX_new failed\n");
        goto cleanup;
    }

    // Load server certificate and private key
    if (wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        unsigned long err_code = wolfSSL_ERR_get_error();
        fprintf(stderr, "ERROR: failed to load %s: %s\n", CERT_FILE,
                wolfSSL_ERR_reason_error_string(err_code));
        goto cleanup;
    }
    fprintf(stderr, "Server certificate loaded.\n");

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        unsigned long err_code = wolfSSL_ERR_get_error();
        fprintf(stderr, "ERROR: failed to load %s: %s\n", KEY_FILE,
                wolfSSL_ERR_reason_error_string(err_code));
        goto cleanup;
    }
    fprintf(stderr, "Server private key loaded.\n");

    // Initialize and set the QUIC method on the CTX
    init_quic_method(&quic_method_actual);
    if (wolfSSL_CTX_set_quic_method(ctx, &quic_method_actual) != WOLFSSL_SUCCESS) {
        unsigned long err_code = wolfSSL_ERR_get_error();
        fprintf(stderr, "ERROR: wolfSSL_CTX_set_quic_method failed: %s\n",
                wolfSSL_ERR_reason_error_string(err_code));
        goto cleanup;
    }
    fprintf(stderr, "QUIC method set on CTX.\n");

    // Create WOLFSSL object for the connection
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "ERROR: wolfSSL_new failed\n");
        goto cleanup;
    }

    // Set the QuicSocketContext as app data for this SSL object
    wolfSSL_set_app_data(ssl, &socket_ctx);

    // Server-side QUIC transport parameters (set on SSL object)
    static const byte tp_params_s[] = {
        0x00, 0x05, /* id=initial_max_data */
        0x00, 0x04, /* length=4 */
        0x00, 0x00, 0x00, 0x00 /* value=0 */
        // Add other parameters as needed
    };
    if (wolfSSL_set_quic_transport_params(ssl, tp_params_s, sizeof(tp_params_s)) != WOLFSSL_SUCCESS) {
         // For SSL object specific functions, get error from SSL object
         int ssl_err = wolfSSL_get_error(ssl, 0);
         char lerr_buffer[WOLFSSL_MAX_ERROR_SZ];
         wolfSSL_ERR_error_string_n(ssl_err, lerr_buffer, sizeof(lerr_buffer));
         fprintf(stderr, "ERROR: wolfSSL_set_quic_transport_params failed: %s (%d)\n",
                 lerr_buffer, ssl_err);
         goto cleanup;
    }
    fprintf(stderr, "QUIC transport parameters set on SSL object.\n");

    // --- Listening and Handshake Loop ---
    fprintf(stderr, "QUIC Server listening on %s:%d...\n", SERVER_HOST, SERVER_PORT);

    // 1. Receive initial packet from a client
    fprintf(stderr, "Waiting for initial client packet...\n");
    socket_ctx.peer_addr_len = sizeof(socket_ctx.peer_addr); // Important!
    ssize_t len_recv = recvfrom(socket_ctx.sock_fd, recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr*)&socket_ctx.peer_addr,
                                &socket_ctx.peer_addr_len);
    if (len_recv < 0) {
        perror("ERROR: Initial recvfrom failed");
        goto cleanup;
    }
    socket_ctx.connected = 1; // Mark that we have a peer
    char peer_ip_str[INET6_ADDRSTRLEN];
    inet_ntop(socket_ctx.peer_addr.ss_family,
              socket_ctx.peer_addr.ss_family == AF_INET ?
                  (void*)&((struct sockaddr_in*)&socket_ctx.peer_addr)->sin_addr :
                  (void*)&((struct sockaddr_in6*)&socket_ctx.peer_addr)->sin6_addr,
              peer_ip_str, sizeof(peer_ip_str));
    int peer_port = ntohs(socket_ctx.peer_addr.ss_family == AF_INET ?
                          ((struct sockaddr_in*)&socket_ctx.peer_addr)->sin_port :
                          ((struct sockaddr_in6*)&socket_ctx.peer_addr)->sin6_port);

    fprintf(stderr, "Received initial %zd bytes from client %s:%d\n", len_recv, peer_ip_str, peer_port);


    // 2. Provide initial data to wolfSSL
    // For the first packet, the level is wolfssl_encryption_initial
    if (wolfSSL_provide_quic_data(ssl, wolfssl_encryption_initial, recv_buf, len_recv) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: wolfSSL_provide_quic_data (initial) failed: %s\n",
                wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl,0)));
        goto cleanup;
    }

    // 3. Start/Process handshake
    ret = wolfSSL_accept(ssl); // Initial call

    int iterations = 0;
    while (ret != WOLFSSL_SUCCESS && iterations < MAX_HANDSHAKE_ITERATIONS) {
        int err = wolfSSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ) {
            fprintf(stderr, "Handshake: WANT_READ. Waiting for data from client %s:%d...\n", peer_ip_str, peer_port);

            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(socket_ctx.sock_fd, &read_fds);
            struct timeval timeout;
            timeout.tv_sec = 10; // 10 second timeout for select
            timeout.tv_usec = 0;

            int activity = select(socket_ctx.sock_fd + 1, &read_fds, NULL, NULL, &timeout);
            if (activity < 0) {
                perror("Handshake: select error");
                ret = SSL_FATAL_ERROR; break;
            }
            if (activity == 0) {
                fprintf(stderr, "Handshake: Timeout waiting for data from client.\n");
                ret = wolfSSL_quic_read_write(ssl); // Allow wolfSSL to process potential timeouts
                 if (wolfSSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ) {
                    fprintf(stderr, "Handshake: Still WANT_READ after select timeout and read_write. Assuming client timeout.\n");
                    ret = SSL_FATAL_ERROR;
                }
                continue;
            }

            if (FD_ISSET(socket_ctx.sock_fd, &read_fds)) {
                // For this simple server, we assume data continues to come from the same peer
                len_recv = recvfrom(socket_ctx.sock_fd, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
                if (len_recv < 0) {
                    perror("Handshake: recvfrom failed");
                    ret = SSL_FATAL_ERROR; break;
                }
                fprintf(stderr, "Handshake: Received %zd bytes from client.\n", len_recv);

                WOLFSSL_ENCRYPTION_LEVEL read_level = wolfSSL_quic_read_level(ssl);
                if (wolfSSL_provide_quic_data(ssl, read_level, recv_buf, len_recv) != WOLFSSL_SUCCESS) {
                    fprintf(stderr, "ERROR: wolfSSL_provide_quic_data failed: %s\n",
                            wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl,0)));
                    ret = SSL_FATAL_ERROR; break;
                }
            }
            ret = wolfSSL_quic_read_write(ssl);

        } else if (err == SSL_ERROR_WANT_WRITE) {
            fprintf(stderr, "Handshake: WANT_WRITE. Data sent by callback. Expecting read.\n");
            ret = wolfSSL_quic_read_write(ssl);
        } else {
            wolfSSL_ERR_error_string_n(err, err_buffer, sizeof(err_buffer));
            fprintf(stderr, "ERROR: Handshake failed with error %d: %s\n", err,
                    err_buffer);
            goto cleanup;
        }
        iterations++;
    }

    if (ret != WOLFSSL_SUCCESS) {
        int last_err = wolfSSL_get_error(ssl, ret);
        wolfSSL_ERR_error_string_n(last_err, err_buffer, sizeof(err_buffer));
        fprintf(stderr, "ERROR: QUIC Handshake failed after %d iterations for client %s:%d. Last ret: %d, SSL error: %d (%s)\n",
                iterations, peer_ip_str, peer_port, ret, last_err, err_buffer);
        goto cleanup;
    }

    if (!wolfSSL_is_init_finished(ssl)) {
        fprintf(stderr, "ERROR: Handshake loop completed, but wolfSSL_is_init_finished is false.\n");
        goto cleanup;
    }
    fprintf(stderr, "QUIC Handshake Complete with client %s:%d!\n", peer_ip_str, peer_port);

    // --- Application Data Exchange ---
    fprintf(stderr, "Waiting for message from client...\n");
    int app_data_tries = 0;
    int client_msg_received = 0;
    while(app_data_tries < 10 && !client_msg_received) { // Try a few times or until message received
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(socket_ctx.sock_fd, &read_fds);
        struct timeval timeout;
        timeout.tv_sec = 5; // 5 seconds
        timeout.tv_usec = 0;

        int activity = select(socket_ctx.sock_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (activity < 0) {
            perror("App Data: select error");
            break;
        }
        if (activity == 0) {
            fprintf(stderr, "App Data: Timeout waiting for client message.\n");
            app_data_tries++;
            continue;
        }

        if (FD_ISSET(socket_ctx.sock_fd, &read_fds)) {
            len_recv = recvfrom(socket_ctx.sock_fd, recv_buf, sizeof(recv_buf) -1, 0, NULL, NULL);
            if (len_recv < 0) {
                perror("App Data: recvfrom failed");
                break;
            }
            fprintf(stderr, "App Data: Received %zd encrypted bytes from client.\n", len_recv);

            if (wolfSSL_provide_quic_data(ssl, wolfssl_encryption_application, recv_buf, len_recv) != WOLFSSL_SUCCESS) {
                fprintf(stderr, "ERROR: wolfSSL_provide_quic_data (app) failed: %s\n",
                        wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl,0)));
                break;
            }

            ret = wolfSSL_read(ssl, recv_buf, sizeof(recv_buf) - 1);
            if (ret > 0) {
                recv_buf[ret] = '\0';
                fprintf(stderr, "SERVER: Received message: \"%s\"\n", (char*)recv_buf);
                client_msg_received = 1;

                // Send response
                fprintf(stderr, "SERVER: Sending response: \"%s\"\n", SERVER_RESPONSE);
                ret = wolfSSL_write(ssl, (const unsigned char*)SERVER_RESPONSE, strlen(SERVER_RESPONSE));
                if (ret < 0) {
                    fprintf(stderr, "ERROR: wolfSSL_write (app) failed: %s\n",
                            wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl,ret)));
                } else {
                    fprintf(stderr, "SERVER: Response sent.\n");
                }
                break; // Exit after one exchange for this example
            } else {
                int err = wolfSSL_get_error(ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    fprintf(stderr, "App Data: wolfSSL_read wants more data.\n");
                    app_data_tries++;
                    continue;
                }
                fprintf(stderr, "ERROR: wolfSSL_read (app) failed: %s\n",
                        wolfSSL_ERR_reason_error_string(err));
                break;
            }
        }
    }
    if (!client_msg_received) {
        fprintf(stderr, "App Data: Did not receive expected message from client.\n");
    }


cleanup:
    fprintf(stderr, "Cleaning up server resources...\n");
    if (socket_ctx.sock_fd != -1) {
        close(socket_ctx.sock_fd);
        socket_ctx.sock_fd = -1;
    }
    if (ssl != NULL) {
        wolfSSL_free(ssl);
    }
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
    }
    wolfSSL_Cleanup();
    fprintf(stderr, "Server cleanup complete.\n");

    return (ret > 0 || (ssl != NULL && wolfSSL_is_init_finished(ssl))) ? 0 : -1;
}
