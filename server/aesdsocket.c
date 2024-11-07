#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
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

#if 1 != USE_AESD_CHAR_DEVICE
static const char* tmp_file = "/var/tmp/aesdsocketdata";
#else
static const char* tmp_file = "dev/aesdchar"
#endif

static int sfd = -1;  // Socket file descriptor

static struct addrinfo* addr = NULL;

static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

struct conn_data_t
{
    char buffer[BUFFER_SIZE];      // Used to store the data read from a socket
    char tmp_buffer[BUFFER_SIZE];  // Used to store data from a packet after a new line
};

struct thread_data_t
{
    pthread_t thread_id;
    bool is_done;
    bool is_started;
    int fd;
    struct conn_data_t* p_data;
    struct thread_data_t* next;
};

static struct thread_data_t* head = NULL;

timer_t timerid = NULL;

struct thread_data_t* get_new_thread_data(void)
{
    struct conn_data_t* new_data = malloc(sizeof(struct conn_data_t));
    memset((void*)new_data, 0, sizeof(new_data));
    struct thread_data_t* new_entry = malloc(sizeof(struct thread_data_t));
    new_entry->p_data = new_data;
    new_entry->is_done = false;
    new_entry->next = NULL;
    return new_entry;
}

void cleanup_and_free_thread_data(struct thread_data_t* thread_data)
{
    if (NULL == thread_data)
    {
        return;
    }
    printf("Closing connection with file descriptor %d\n", thread_data->fd);
    close(thread_data->fd);
    free(thread_data->p_data);
    free(thread_data);
}

static inline void close_files(void)
{
    close(sfd);
}

static inline void cleanup_memory(void)
{
    if (NULL != addr)
    {
        freeaddrinfo(addr);
        addr = NULL;
    }

    if (NULL != timerid)
    {
        timer_delete(timerid);
    }

    struct thread_data_t* current = head;
    while (NULL != current)
    {
        head = current->next;
        printf("\nRemove thread with id %ld \n", current->thread_id);
        pthread_join(current->thread_id, NULL);
        cleanup_and_free_thread_data(current);
        current = head;
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

static int read_safe(int fd, void* buffer, size_t n_bytes)
{
    pthread_mutex_lock(&file_mutex);
    int res = read(fd, buffer, n_bytes);
    pthread_mutex_unlock(&file_mutex);
    return res;
}

static int write_safe(void* buffer, size_t n_bytes)
{
    pthread_mutex_lock(&file_mutex);
    int retval = -1;
    int wfd = open(tmp_file, O_APPEND | O_WRONLY);
    if (wfd > 0)
    {
        retval = write(wfd, buffer, n_bytes);
        close(wfd);
    }
    pthread_mutex_unlock(&file_mutex);
    return retval;
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

static bool wait_for_connection(int* conn_fd)
{
    // Do not use assert. Instead, do as if no connection could be received.
    if (NULL == conn_fd)
    {
        syslog(LOG_ERR, "NULL passed to wait_for_connection");
        return false;
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
            return false;
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
    return true;
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
                if (-1 == write_safe(p_conn_data->buffer, str_len))
                {
                    syslog(LOG_ERR, "Could not write to tmp file");
                    terminate_with_error();
                }

                did_find_eol = true;
            }
            else
            {
                // No newline -> packet not finished -> write entire buffer to file
                if (-1 == write_safe(p_conn_data->buffer, len))
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

static void send_back_entire_file(const char* tmp_file, int conn_fd)
{
    int read_fd = open(tmp_file, O_RDONLY);
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
            while (-1 == write(conn_fd, buffer, rd_len))
            {
                int err = errno;
                if ((err == EAGAIN) || (err == EWOULDBLOCK))
                {
                    continue;
                }
                else
                {
                    syslog(LOG_ERR, "Error sending data");
                    printf("Error reading sending data\n");

                    free(buffer);
                    close(read_fd);
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

static void* worker_thread(void* thread_param)
{
    if (NULL == thread_param)
    {
        return NULL;
    }
    struct thread_data_t* params = (struct thread_data_t*)thread_param;

    printf("Starting worker thread with id %ld...\n", params->thread_id);

    write_received_data_to_file(params->fd, params->p_data);
    send_back_entire_file(tmp_file, params->fd);

    // Write stream content coming after the newline to the file
    if (-1 == write_safe(params->p_data->tmp_buffer, strlen(params->p_data->tmp_buffer)))
    {
        syslog(LOG_ERR, "Could not write to tmp file");
        terminate_with_error();
    }

    params->is_done = true;

    printf("Worker thread with id %ld finished!\n", params->thread_id);

    return thread_param;
}

#if 1 != USE_AESD_CHAR_DEVICE
void update_timestamp(int signum)
{
    if (SIGRTMIN == signum)
    {
        time_t now;
        struct tm* tm_info;
        char buffer[128];

        time(&now);
        tm_info = localtime(&now);
        strftime(buffer, sizeof(buffer), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", tm_info);

        printf("Writing time to file : %s", buffer);
        if (-1 == write_safe(buffer, strlen(buffer)))
        {
            syslog(LOG_ERR, "Could not write timestamp to file");
            terminate_with_error();
        }
    }
}

static void setup_and_start_timer(void)
{
    struct sigevent sev;
    struct itimerspec its;
    struct sigaction sa;

    // Set up the signal handler for the timer signal
    sa.sa_flags = 0;
    sa.sa_handler = update_timestamp;
    sigemptyset(&sa.sa_mask);
    if (-1 == sigaction(SIGRTMIN, &sa, NULL))
    {
        syslog(LOG_ERR, "sigaction call failed");
        terminate_with_error();
    }

    // Create the timer
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    sev.sigev_value.sival_ptr = &timerid;
    if (-1 == timer_create(CLOCK_REALTIME, &sev, &timerid))
    {
        syslog(LOG_ERR, "timer_create call failed");
        terminate_with_error();
    }

    // Set the timer to expire after 10 seconds and then every 10 seconds
    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 10;
    its.it_interval.tv_nsec = 0;
    if (-1 == timer_settime(timerid, 0, &its, NULL))
    {
        syslog(LOG_ERR, "timer_settime call failed");
        terminate_with_error();
    }
}
#endif

int main(int argc, char* argv[])
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    openlog("aesdsocketsyslog", 0, LOG_USER);

    get_server_address_and_bind();

    start_daemon_if_needed(argc, argv);

#if 1 != USE_AESD_CHAR_DEVICE
    setup_and_start_timer();

    int fd = creat(tmp_file, 0644);
    if (fd < 0)
    {
        printf("Could not create tmp file\n");
        terminate_with_error();
    }
    else
    {
        close(fd);
    }
#endif

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
        int conn_fd = 0;
        if (!wait_for_connection(&conn_fd))
        {
            continue;
        }

        struct thread_data_t* new_thread_data = get_new_thread_data();
        new_thread_data->fd = conn_fd;
        int res = pthread_create(&new_thread_data->thread_id, NULL, worker_thread, new_thread_data);
        if (res == -1)
        {
            syslog(LOG_ERR, "Could not create thread for connection %d", conn_fd);
            printf("Could not create thread for connection %d\n", conn_fd);
            cleanup_and_free_thread_data(new_thread_data);
        }
        else
        {
            if (NULL != head)
            {
                printf("Already a head\n");
                new_thread_data->next = head;
            }
            head = new_thread_data;

            printf("Updated head\n");

            struct thread_data_t* previous = NULL;
            struct thread_data_t* current = head;
            while (NULL != current)
            {
                printf("Checking if thread with id %ld is finished... ", current->thread_id);
                if (current->is_done)
                {
                    printf("Waiting for thread to join... ");
                    pthread_join(current->thread_id, NULL);
                    printf("done!\n");
                    if (NULL == previous)
                    {
                        head = current->next;
                    }
                    else
                    {
                        previous->next = current->next;
                    }
                    cleanup_and_free_thread_data(current);
                    current = previous->next;
                }
                else
                {
                    printf("not finished\n");
                    previous = current;
                    current = current->next;
                }
            }
        }
    }

    terminate_normally();
}
