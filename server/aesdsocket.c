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
#include <pthread.h>
#include <signal.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>

#define BUFFER_SIZE 1024
#define BURST_SIZE  (BUFFER_SIZE - 1)

volatile __sig_atomic_t stop_sig;

static int sfd = -1;  // Socket file descriptor
static int wfd = -1;  // Write temporary file descriptor

static struct addrinfo* addr = NULL;

static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

struct conn_data_t
{
    char buffer[BUFFER_SIZE];      // Used to store the data read from a socket
    char tmp_buffer[BUFFER_SIZE];  // Used to store data from a packet after a new line
};

struct thread_data_t
{
    int fd;
    struct conn_data_t* p_data;
    bool is_done;
    SLIST_ENTRY(thread_data_t)
    next;
};

SLIST_HEAD(list, thread_data_t)
thread_data_list;

struct thread_data_t* get_new_thread_data(void)
{
    struct conn_data_t* new_data = malloc(sizeof(struct conn_data_t));
    memset((void*)new_data, 0, sizeof(new_data));
    struct thread_data_t* new_entry = malloc(sizeof(struct thread_data_t));
    new_entry->p_data = new_data;
    new_entry->is_done = false;
    return new_entry;
}

static inline void close_files(void)
{
    close(sfd);
    close(wfd);
}

static inline void cleanup_memory(void)
{
    if (NULL != addr)
    {
        freeaddrinfo(addr);
        addr = NULL;
    }

    // TODO : request all threads to terminate
    // TODO : join all threads

    struct thread_data_t* entry = NULL;
    while ((entry = SLIST_FIRST(&thread_data_list)) != NULL)
    {
        SLIST_REMOVE_HEAD(&thread_data_list, next);
        close(entry->fd);
        free(entry->p_data);
        free(entry);
    }
}

static inline void terminate_normally(void)
{
    printf("Terminating normally\n");
    cleanup_memory();
    close_files();
    exit(EXIT_SUCCESS);
}

static inline void terminate_with_error(void)
{
    printf("Terminating because of an error\n");
    cleanup_memory();
    close_files();
    exit(-1);
}

// TODO : make rw from/to file thread-safe : wrapper around read and write functions

static int read_safe(int fd, void* buffer, size_t n_bytes)
{
    pthread_mutex_lock(&file_mutex);
    int res = read(fd, buffer, n_bytes);
    pthread_mutex_unlock(&file_mutex);
    return res;
}

static int write_safe(int fd, void* buffer, size_t n_bytes)
{
    pthread_mutex_lock(&file_mutex);
    int res = write(fd, buffer, n_bytes);
    pthread_mutex_unlock(&file_mutex);
    return res;
}

static void start_daemon_if_needed(int argc, char* argv[])
{
    if ((argc == 2) && (0 == strcmp(argv[1], "-d")))
    {
        // Start as a daemon:
        pid_t pid = fork();
        if (pid > 0)
        {
            printf("Started daemon with pid %d, exiting\n", pid);
            syslog(LOG_INFO, "Started daemon with pid %d", pid);
            terminate_normally();
        }
        else if (pid < 0)
        {
            perror("Could not start daemon");
            syslog(LOG_ERR, "Could not start daemon");
        }
        else
        {
            printf("Running as daemon...\n");

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

static void create_log_file(const char* filename)
{
    wfd = creat(filename, 0644);
    if (-1 == wfd)
    {
        syslog(LOG_ERR, "Could not create tmp file");
        printf("Got stop signal\n");
        terminate_with_error();
    }
}

static void get_server_address_and_bind(void)
{
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
}

static struct conn_data_t* wait_for_connection(int* conn_fd)
{
    // Do not use assert. Instead, do as if no connection could be received.
    if (NULL == conn_fd)
    {
        syslog(LOG_ERR, "NULL passed to wait_for_connection");
        return NULL;
    }

    struct sockaddr peer_addr;
    socklen_t length = sizeof(peer_addr);
    int fd = accept4(sfd, &peer_addr, &length, SOCK_NONBLOCK);
    *conn_fd = fd;
    int err = errno;
    if (-1 == fd)
    {
        if ((err == EAGAIN) || (err == EWOULDBLOCK))
        {
            return NULL;
        }
        else
        {
            syslog(LOG_ERR, "No connection accepted");
            terminate_with_error();
        }
    }
    else
    {
        printf("Got connection file descriptor %d\n", fd);
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
    struct conn_data_t* p_conn_data = malloc(sizeof(struct conn_data_t));
    return p_conn_data;
}

static void write_received_data_to_file(int conn_fd, struct conn_data_t* p_conn_data)
{
    if (NULL == p_conn_data)
    {
        syslog(LOG_ERR, "NULL passed to write_received_data_to_file");
        return;
    }

    // Setup buffer to receive data
    memset((void*)p_conn_data->buffer, 0, sizeof(char) * BUFFER_SIZE);

    // Receive data until end of packet
    bool did_find_eol = false;
    while (!did_find_eol)
    {
        int len = read(conn_fd, p_conn_data->buffer, BURST_SIZE);
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
            p_conn_data->buffer[len] = '\0';  // For string handling functions
            char* eol_ptr = strstr(p_conn_data->buffer, "\n");
            if (NULL != eol_ptr)
            {
                printf("Got new line!\n");

                // Copy remaining bytes to the buffer so they are not lost
                // Safe to use strcpy because we added \0 to the end of the data buffer
                char* remaining_string = &eol_ptr[1];
                strcpy(p_conn_data->tmp_buffer, remaining_string);

                // Write the bytes up to the newline to the file
                eol_ptr[1] = '\0';  // for string length
                size_t str_len = strlen(p_conn_data->buffer);
                printf("Read %lu bytes until end of line\n", str_len);
                if (-1 == write_safe(wfd, p_conn_data->buffer, str_len))
                {
                    syslog(LOG_ERR, "Could not write to tmp file");
                    terminate_with_error();
                }

                did_find_eol = true;
            }
            else
            {
                // No newline -> packet not finished -> write entire buffer to file
                if (-1 == write_safe(wfd, p_conn_data->buffer, len))
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
}

static void send_back_entire_file(const char* filename, int conn_fd)
{
    int read_fd = open(filename, O_RDONLY);
    if (-1 == read_fd)
    {
        syslog(LOG_ERR, "Could not open tmp file for reading");
        return;
    }

    char* buffer = malloc(sizeof(char) * BUFFER_SIZE);
    if (NULL == buffer)
    {
        syslog(LOG_ERR, "Could not allocate memory in send_back_entire_file");
        return;
    }

    while (true)
    {
        // TODO : mutex
        int rd_len = read_safe(read_fd, buffer, BUFFER_SIZE);
        if (-1 == rd_len)
        {
            syslog(LOG_ERR, "Error reading from tmp file");
            printf("Error reading from tmp file\n");
            free(buffer);
            close(read_fd);
            terminate_with_error();
        }
        else if (rd_len > 0)
        {
            // TODO : mutex
            while (-1 == write_safe(conn_fd, buffer, rd_len))
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

    // clean-up resources allocated locally
    free(buffer);
    close(read_fd);
}

int main(int argc, char* argv[])
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    openlog("aesdsocketsyslog", 0, LOG_USER);

    const char* filename = "/var/tmp/aesdsocketdata";
    create_log_file(filename);

    get_server_address_and_bind();

    start_daemon_if_needed(argc, argv);

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

    while (true)
    {
        // TODO : spawn new thread
        struct thread_data_t thread_data;
        thread_data.p_data = wait_for_connection(&thread_data.fd);
        if (NULL == thread_data.p_data)
        {
            close(thread_data.fd);
            continue;
        }

        write_received_data_to_file(thread_data.fd, thread_data.p_data);
        send_back_entire_file(filename, thread_data.fd);

        // Write stream content coming after the newline to the file
        if (-1 == write_safe(wfd, thread_data.p_data->tmp_buffer, strlen(thread_data.p_data->tmp_buffer)))
        {
            syslog(LOG_ERR, "Could not write to tmp file");
            terminate_with_error();
        }

        printf("Closing connection\n");
        close(thread_data.fd);
        free(thread_data.p_data);
    }

    terminate_normally();
}
