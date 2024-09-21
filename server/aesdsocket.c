#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>

#define BUFFER_SIZE 1024
#define BURST_SIZE  (BUFFER_SIZE - 1)

volatile __sig_atomic_t stop_sig;

static int sfd = -1;  // Socket file descriptor
static int cfd = -1;  // Connection file descriptor
static int wfd = -1;  // Write temporary file descriptor
static int rfd = -1;  // Read temporary file descriptor

static struct addrinfo* addr = NULL;

static inline void close_files()
{
    close(sfd);
    close(cfd);
    close(wfd);
    close(rfd);
}

static inline void cleanup_memory()
{
    if (NULL != addr)
    {
        freeaddrinfo(addr);
        addr = NULL;
    }
}

static inline void terminate_normally()
{
    printf("Terminating normally\n");
    cleanup_memory();
    close_files();
    exit(EXIT_SUCCESS);
}

static inline void terminate_with_error()
{
    printf("Terminating because of an error\n");
    cleanup_memory();
    close_files();
    exit(-1);
}

static void start_deamon_if_needed(int argc, char* argv[])
{
    if ((argc == 2) && (0 == strcmp(argv[1], "-d")))
    {
        // Start as a deamon:
        pid_t pid = fork();
        if (pid > 0)
        {
            printf("Started deamon with pid %d, exiting\n", pid);
            syslog(LOG_INFO, "Started deamon with pid %d", pid);
            terminate_normally();
        }
        else if (pid < 0)
        {
            perror("Could not start deamon");
            syslog(LOG_ERR, "Could not start deamon");
        }
        else
        {
            printf("Running as deamon...\n");

            (void)setsid();
            chdir("/");
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            open("/dev/null", O_RDONLY);
            open("/dev/null", O_RDWR);
            open("/dev/null", O_RDWR);
        }
    }
}

static void handle_signal(int signal)
{
    if (signal == SIGINT || signal == SIGTERM)
    {
        printf("\nGot SIGINT or SIGTERM\n");
        syslog(LOG_INFO, "Caught SIGINT or SIGTERM, exiting");
        terminate_normally();
    }
}

int main(int argc, char* argv[])
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    openlog("aesdsocketsyslog", 0, LOG_USER);

    char buffer[BUFFER_SIZE];

    // Create the log file
    char* filename = "/var/tmp/aesdsocketdata";
    wfd = creat(filename, 0644);
    if (-1 == wfd)
    {
        syslog(LOG_ERR, "Could not create tmp file");
        printf("Got stop signal\n");
        terminate_with_error();
    }

    // Get the address
    struct addrinfo hints;
    memset((void*)&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0; /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    int status = getaddrinfo(NULL, "9000", &hints, &addr);
    if (0 != status)
    {
        syslog(LOG_ERR, "Could not get address info: %s", gai_strerror(status));
        terminate_with_error();
    }

    struct addrinfo* next_addr;
    for (next_addr = addr; next_addr != NULL; next_addr = next_addr->ai_next)
    {
        sfd = socket(next_addr->ai_family, next_addr->ai_socktype | SOCK_NONBLOCK, next_addr->ai_protocol);
        if (-1 != sfd)
        {
            if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
            {
                perror("setsockopt(SO_REUSEADDR) failed");
            }
            if (0 == bind(sfd, next_addr->ai_addr, next_addr->ai_addrlen))
            {
                syslog(LOG_USER, "Bind successful");
                printf("Bind successful\n");

                break;  // Success
            }
            else
            {
                perror("Could not bind");
            }
            close(sfd);
        }
        else
        {
            printf("Could not create socket, trying the next addr\n");
        }
    }
    freeaddrinfo(addr);  // No longer needed
    addr = NULL;
    if (NULL == next_addr)
    {
        fprintf(stderr, "Could not bind\n");
        syslog(LOG_ERR, "Could not bind");
        terminate_with_error();
    }

    start_deamon_if_needed(argc, argv);

    // Listen for connection on the socket
    if (-1 == listen(sfd, 42))
    {
        syslog(LOG_ERR, "Could not listen for connection on the socket");
        terminate_with_error();
    }
    else
    {
        syslog(LOG_INFO, "Listen for connection successful");
        printf("Listen for connection successful\n");
    }

    while (!stop_sig)
    {
        // Wait for a connection
        struct sockaddr peer_addr;
        socklen_t length = sizeof(peer_addr);
        cfd = accept4(sfd, &peer_addr, &length, SOCK_NONBLOCK);
        int err = errno;
        if (-1 == cfd)
        {
            if ((err == EAGAIN) || (err == EWOULDBLOCK))
            {
                continue;
            }
            else
            {
                syslog(LOG_ERR, "No connection accepted");
                terminate_with_error();
            }
        }
        else
        {
            printf("Got connection file descriptor %d\n", cfd);
            char host[NI_MAXHOST];
            char serv[NI_MAXSERV];
            int s = getnameinfo(&peer_addr, length, host, NI_MAXHOST, serv, NI_MAXSERV, 0);
            if (0 == s)
            {
                syslog(LOG_INFO, "Accepted connection from %s", host);
                printf("Accepted from %s:%s\n", host, serv);
            }
            else
            {
                printf("Error getting info: %s\n", gai_strerror(s));
            }
        }

        // Setup buffer to receive data
        memset((void*)buffer, 0, sizeof(char) * BUFFER_SIZE);

        // Receive data until end of packet
        bool did_find_eol = false;
        char tmp_buffer[BUFFER_SIZE];
        while (!did_find_eol)
        {
            int len = read(cfd, buffer, BURST_SIZE);
            if (-1 == len)
            {
                int err = errno;
                if ((err != EAGAIN) && (err != EWOULDBLOCK))
                {
                    perror("Could not read stream");
                    syslog(LOG_ERR, "Could not read stream");
                    terminate_with_error();
                }
            }
            else if (len > 0)
            {
                printf("Read %d bytes\n", len);
                buffer[len] = '\0';  // For string handling functions
                char* eol_ptr = strstr(buffer, "\n");
                if (NULL != eol_ptr)
                {
                    printf("Got new line!\n");

                    // Copy remaining bytes to the buffer so they are not lost
                    char* remaining_string = &eol_ptr[1];
                    strcpy(tmp_buffer, remaining_string);

                    // Write the bytes up to the newline to the file
                    eol_ptr[1] = '\0';  // for string length
                    size_t str_len = strlen(buffer);
                    printf("Read %lu bytes until end of line\n", str_len);
                    if (-1 == write(wfd, buffer, str_len))
                    {
                        syslog(LOG_ERR, "Could not write to tmp file");
                        terminate_with_error();
                    }

                    did_find_eol = true;
                }
                else
                {
                    // No newline -> packet not finished -> write entire buffer to file
                    if (-1 == write(wfd, buffer, len))
                    {
                        syslog(LOG_ERR, "Could not write to tmp file");
                        terminate_with_error();
                    }
                }
            }
            else
            {
                // Try again in the next loop execution
            }
        }

        // Send the file's content back
        rfd = open(filename, O_RDONLY);
        if (-1 == rfd)
        {
            syslog(LOG_ERR, "Could not open tmp file for reading");
        }

        while (true)
        {
            int rd_len = read(rfd, buffer, BUFFER_SIZE);
            if (-1 == rd_len)
            {
                syslog(LOG_ERR, "Error reading from tmp file");
                printf("Error reading from tmp file\n");
                terminate_with_error();
            }
            else if (rd_len > 0)
            {
                while (-1 == write(cfd, buffer, rd_len))
                {
                    int err = errno;
                    if ((err == EAGAIN) || (err == EWOULDBLOCK))
                    {
                        if (stop_sig)
                        {
                            break;
                        }
                        continue;
                    }
                    else
                    {
                        syslog(LOG_ERR, "Error sending data");
                        printf("Error reading sending data\n");
                        terminate_with_error();
                    }
                }
            }
            else
            {
                // No more bytes...
                printf("No more bytes to write\n");
                break;
            }

            printf("Wrote %d bytes to socket\n", rd_len);
        }

        // Write stream content coming after the newline to the file
        if (-1 == write(wfd, tmp_buffer, strlen(tmp_buffer)))
        {
            syslog(LOG_ERR, "Could not write to tmp file");
            terminate_with_error();
        }

        printf("Closing connection\n");
        close(cfd);
        close(rfd);
    }

    // Clean-up for next packet
    memset((void*)buffer, 0, sizeof(char) * BUFFER_SIZE);

    terminate_normally();
}
