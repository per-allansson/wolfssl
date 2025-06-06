/* Example QUIC client using socket-based I/O */

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

#include <wolfssl/ssl.h> // Other wolfSSL headers
#include <wolfssl/quic.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "quic_utils.h" // Local project headers

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 11111
#define MAX_RECV_BUF 2048
#define MAX_HANDSHAKE_ITERATIONS 20 // Safety break for handshake loop
#define CLIENT_MESSAGE "Hello QUIC Server!"

int main(int argc, char **argv)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_QUIC_METHOD quic_method_actual;
    QuicSocketContext socket_ctx;
    int ret = 0;
    char err_buffer[WOLFSSL_MAX_ERROR_SZ];
    char recv_buf[MAX_RECV_BUF];

    (void)argc;
    (void)argv;

    // Initialize QuicSocketContext
    memset(&socket_ctx, 0, sizeof(QuicSocketContext));
    socket_ctx.sock_fd = -1;
    socket_ctx.is_server = 0;

    fprintf(stderr, "Initializing wolfSSL for QUIC client...\n");
    wolfSSL_Init();

    // Create UDP socket and get server address
    // For the client, create_udp_socket stores the server's resolved address
    // in socket_ctx.peer_addr and socket_ctx.peer_addr_len.
    // It also stores the local address the socket implicitly binds to in local_addr.
    socket_ctx.sock_fd = create_udp_socket(SERVER_HOST, SERVER_PORT, 0,
                                           &socket_ctx.peer_addr,
                                           &socket_ctx.peer_addr_len);
    if (socket_ctx.sock_fd < 0) {
        fprintf(stderr, "ERROR: create_udp_socket failed\n");
        // No goto cleanup yet, as wolfSSL objects aren't created
        wolfSSL_Cleanup();
        return -1;
    }
    // For client, after create_udp_socket, peer_addr is set. Mark as "connected".
    socket_ctx.connected = 1;


    // Create WOLFSSL_CTX
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "ERROR: wolfSSL_CTX_new failed\n");
        goto cleanup;
    }

    // Initialize and set the QUIC method using our utility functions
    init_quic_method(&quic_method_actual);
    // Note: For client, wolfSSL_set_quic_method is used on SSL object, not CTX
    // if (wolfSSL_CTX_set_quic_method(ctx, &quic_method_actual) != WOLFSSL_SUCCESS) {
    //     fprintf(stderr, "ERROR: wolfSSL_CTX_set_quic_method failed\n");
    //     goto cleanup;
    // }

    // Create WOLFSSL object
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "ERROR: wolfSSL_new failed\n");
        goto cleanup;
    }

    // Set the QuicSocketContext as app data
    wolfSSL_set_app_data(ssl, &socket_ctx);

    // Set QUIC method on SSL object
    if (wolfSSL_set_quic_method(ssl, &quic_method_actual) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: wolfSSL_set_quic_method failed: %s\n",
                wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, 0)));
        goto cleanup;
    }
    fprintf(stderr, "QUIC method set on WOLFSSL object.\n");

    // Set QUIC transport parameters (essential for QUIC)
    // Using placeholder values; a real application would define meaningful ones.
    static const byte tp_params_c[] = {
        0x00, 0x05, /* id=initial_max_data */
        0x00, 0x04, /* length=4 */
        0x00, 0x00, 0x00, 0x00 /* value=0 */
    };
    if (wolfSSL_set_quic_transport_params(ssl, tp_params_c, sizeof(tp_params_c)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: wolfSSL_set_quic_transport_params failed: %s\n",
                wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, 0)));
        goto cleanup;
    }
    fprintf(stderr, "QUIC transport parameters set.\n");

    // Optionally, set expected ALPN
    // wolfSSL_UseALPN(ssl, "h3", 2, WOLFSSL_ALPN_FAILED_ON_MISMATCH);


    // QUIC Handshake Loop
    fprintf(stderr, "Starting QUIC handshake with %s:%d...\n", SERVER_HOST, SERVER_PORT);
    ret = wolfSSL_connect(ssl); // Initial call to start handshake

    int iterations = 0;
    while (ret != WOLFSSL_SUCCESS && iterations < MAX_HANDSHAKE_ITERATIONS) {
        int err = wolfSSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ) {
            fprintf(stderr, "Handshake: WANT_READ. Waiting for data...\n");

            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(socket_ctx.sock_fd, &read_fds);
            struct timeval timeout;
            timeout.tv_sec = 5; // 5 second timeout for select
            timeout.tv_usec = 0;

            int activity = select(socket_ctx.sock_fd + 1, &read_fds, NULL, NULL, &timeout);
            if (activity < 0) {
                perror("Handshake: select error");
                ret = SSL_FATAL_ERROR; // Simulate a fatal error for loop exit
                break;
            }
            if (activity == 0) {
                fprintf(stderr, "Handshake: Timeout waiting for data from server.\n");
                // Depending on strategy, could retry, or abort.
                // For this example, we might try to call read_write again to see if it wants to send something.
                // Or, if we are sure we are waiting for server's response, this is a timeout.
                ret = wolfSSL_quic_read_write(ssl); // Allow wolfSSL to process potential timeouts or retransmits
                if (wolfSSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ) {
                    fprintf(stderr, "Handshake: Still WANT_READ after select timeout and read_write. Assuming peer timeout.\n");
                    ret = SSL_FATAL_ERROR;
                }
                continue; // Re-check 'ret' at the start of the loop
            }

            if (FD_ISSET(socket_ctx.sock_fd, &read_fds)) {
                struct sockaddr_storage peer_addr_recv;
                socklen_t peer_addr_recv_len = sizeof(peer_addr_recv);
                ssize_t len_recv = recvfrom(socket_ctx.sock_fd, recv_buf, sizeof(recv_buf), 0,
                                            (struct sockaddr*)&peer_addr_recv, &peer_addr_recv_len);

                if (len_recv < 0) {
                    perror("Handshake: recvfrom failed");
                    ret = SSL_FATAL_ERROR; // Loop exit
                    break;
                }
                fprintf(stderr, "Handshake: Received %zd bytes from peer.\n", len_recv);

                // Provide received data to wolfSSL
                // Determine the current encryption level wolfSSL expects data at
                WOLFSSL_ENCRYPTION_LEVEL read_level = wolfSSL_quic_read_level(ssl);
                if (wolfSSL_provide_quic_data(ssl, read_level, (const uint8_t*)recv_buf, len_recv) != WOLFSSL_SUCCESS) {
                    fprintf(stderr, "ERROR: wolfSSL_provide_quic_data failed: %s\n",
                            wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl,0)));
                    ret = SSL_FATAL_ERROR; // Loop exit
                    break;
                }
            }
            // Process the provided data or internal events
            ret = wolfSSL_quic_read_write(ssl);

        } else if (err == SSL_ERROR_WANT_WRITE) {
            // wolfSSL has data to send, which should have been handled by quic_add_handshake_data_cb.
            // This state means the callback was invoked. We should now expect WANT_READ.
            fprintf(stderr, "Handshake: WANT_WRITE. Data was sent by callback. Now expecting read.\n");
            ret = wolfSSL_quic_read_write(ssl); // Or could just set ret to force WANT_READ expectation
        } else {
            // Other error
            wolfSSL_ERR_error_string_n(err, err_buffer, sizeof(err_buffer));
            fprintf(stderr, "ERROR: Handshake failed with error %d: %s\n", err,
                    err_buffer);
            goto cleanup; // Unrecoverable error
        }
        iterations++;
    }

    if (ret != WOLFSSL_SUCCESS) {
        int last_err = wolfSSL_get_error(ssl, ret); // Get the specific error code
        wolfSSL_ERR_error_string_n(last_err, err_buffer, sizeof(err_buffer)); // Use the specific error code
        fprintf(stderr, "ERROR: QUIC Handshake failed after %d iterations. Last ret: %d, SSL error: %d (%s)\n",
                iterations, ret, last_err, err_buffer);
        goto cleanup;
    }

    if (!wolfSSL_is_init_finished(ssl)) {
        fprintf(stderr, "ERROR: Handshake loop completed, but wolfSSL_is_init_finished is false.\n");
        goto cleanup;
    }

    fprintf(stderr, "QUIC Handshake Complete!\n");

    // Application Data Exchange
    fprintf(stderr, "Sending message: %s\n", CLIENT_MESSAGE);
    ret = wolfSSL_write(ssl, CLIENT_MESSAGE, strlen(CLIENT_MESSAGE));
    if (ret < 0) {
        fprintf(stderr, "ERROR: wolfSSL_write failed: %s\n",
                wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl,ret)));
        goto cleanup;
    }

    fprintf(stderr, "Message sent. Waiting for response...\n");
    // Loop to receive data (with timeout)
    int app_data_tries = 0;
    while (app_data_tries < 5) { // Try a few times
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(socket_ctx.sock_fd, &read_fds);
        struct timeval timeout;
        timeout.tv_sec = 2; // 2 second timeout
        timeout.tv_usec = 0;

        int activity = select(socket_ctx.sock_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (activity < 0) {
            perror("App Data: select error");
            break;
        }
        if (activity == 0) {
            fprintf(stderr, "App Data: Timeout waiting for server response.\n");
            app_data_tries++;
            continue;
        }

        if (FD_ISSET(socket_ctx.sock_fd, &read_fds)) {
            ssize_t len_recv = recvfrom(socket_ctx.sock_fd, recv_buf, sizeof(recv_buf) -1 , 0, NULL, NULL);
            if (len_recv < 0) {
                perror("App Data: recvfrom failed");
                break;
            }
            fprintf(stderr, "App Data: Received %zd encrypted bytes from server.\n", len_recv);

            if (wolfSSL_provide_quic_data(ssl, wolfssl_encryption_application, (const uint8_t*)recv_buf, len_recv) != WOLFSSL_SUCCESS) {
                fprintf(stderr, "ERROR: wolfSSL_provide_quic_data (app) failed: %s\n",
                        wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl,0)));
                break;
            }

            ret = wolfSSL_read(ssl, recv_buf, sizeof(recv_buf) - 1);
            if (ret > 0) {
                recv_buf[ret] = '\0';
                printf("CLIENT: Received response: \"%s\"\n", recv_buf);
                break; // Got response
            } else {
                int err = wolfSSL_get_error(ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    fprintf(stderr, "App Data: wolfSSL_read wants more data.\n");
                    app_data_tries++; // Continue waiting
                    continue;
                }
                fprintf(stderr, "ERROR: wolfSSL_read (app) failed: %s\n",
                        wolfSSL_ERR_reason_error_string(err));
                break;
            }
        }
    }
    if (app_data_tries >= 5 && ret <=0) {
         fprintf(stderr, "App Data: Did not receive a response from server.\n");
    }


cleanup:
    fprintf(stderr, "Cleaning up client resources...\n");
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
    fprintf(stderr, "Client cleanup complete.\n");

    return (ret > 0 || wolfSSL_is_init_finished(ssl)) ? 0 : -1; // Success if handshake done and read > 0 or just handshake done
}
