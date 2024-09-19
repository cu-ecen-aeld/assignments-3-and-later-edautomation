#include <errno.h>
#include <fcntl.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#define BUFFER_SIZE 1024
#define BURST_SIZE  (BUFFER_SIZE - 1)

int main(int argc, char* argv[])
{
    openlog("aesdsocketsyslog", 0, LOG_USER);

    // Declared here so we can close them at the end regardless of the success of the program
    int cfd = -1;
    char buffer[BUFFER_SIZE];

    // Create the log file
    char* filename = "/var/tmp/aesdsocketdata";
    int tmp_file_wr_fd = creat(filename, 0644);
    if (-1 == tmp_file_wr_fd)
    {
        syslog(LOG_ERR, "Could not create tmp file");
        goto cleanup_err;
    }
    int tmp_file_rd_fd = -1;

    // Get the address
    struct addrinfo hints;
    struct addrinfo* addr;
    memset((void*)&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0; /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    int status = getaddrinfo(NULL, "9000", &hints, &addr);
    if (0 != status)
    {
        syslog(LOG_ERR, "Could not get address info: %s", gai_strerror(status));
        goto cleanup_err;
    }

    struct addrinfo* next_addr;
    int sfd;
    for (next_addr = addr; next_addr != NULL; next_addr = next_addr->ai_next)
    {
        sfd = socket(next_addr->ai_family, next_addr->ai_socktype, next_addr->ai_protocol);
        if (-1 != sfd)
        {
            if (0 == bind(sfd, next_addr->ai_addr, next_addr->ai_addrlen))
            {
                syslog(LOG_USER, "Bind successful");
                printf("Bind successful\n");

                break; /* Success */
            }
            close(sfd);
        }
        else
        {
            printf("Could not create socket, trying the next addr\n");
        }
    }

    freeaddrinfo(addr);  // No longer needed
    if (NULL == next_addr)
    {
        fprintf(stderr, "Could not bind\n");
        syslog(LOG_ERR, "Could not bind");
    }

    // Listen for connection on the socket
    if (-1 == listen(sfd, 42))
    {
        syslog(LOG_ERR, "Could not listen for connection on the socket");
        goto cleanup_err;
    }
    else
    {
        syslog(LOG_INFO, "Listen for connection successful");
        printf("Listen for connection successful\n");
    }

    // // Wait for a connection
    struct sockaddr peer_addr;
    socklen_t length = sizeof(peer_addr);
    cfd = accept(sfd, &peer_addr, &length);
    if (-1 == cfd)
    {
        syslog(LOG_ERR, "No connection accepted");
        goto cleanup_err;
    }
    else
    {
        char host[NI_MAXHOST];
        char serv[NI_MAXSERV];
        int s = getnameinfo(&peer_addr, length, host, NI_MAXHOST, serv, NI_MAXSERV, 0);
        if (0 == s)
        {
            printf("Accepting from %s:%s\n", host, serv);
        }
        else
        {
            printf("Error getting info: %s\n", gai_strerror(s));
        }
    }

    // // Setup buffer to receive data
    // memset((void*)buffer, 0, sizeof(char) * BUFFER_SIZE);

    // // Receive data until end of packet
    // bool did_find_eol = false;
    // char tmp_buffer[BUFFER_SIZE];
    // while (!did_find_eol)
    // {
    //     int len = read(cfd, buffer, BURST_SIZE);
    //     if (-1 == len)
    //     {
    //         syslog(LOG_ERR, "Could not read stream");
    //         goto cleanup_err;
    //     }
    //     else if (len > 0)
    //     {
    //         buffer[len] = '\0';  // For string handling functions
    //         char* eol_ptr = strstr(buffer, "\n");
    //         if (NULL != eol_ptr)
    //         {
    //             // Copy remaining bytes to the buffer so they are not lost
    //             char* remaining_string = &eol_ptr[1];
    //             strcpy(tmp_buffer, remaining_string);
    //             did_find_eol = true;
    //         }
    //         else
    //         {
    //             // No newline -> packet not finished -> write entire buffer to file
    //             if (-1 == write(tmp_file_wr_fd, buffer, len))
    //             {
    //                 syslog(LOG_ERR, "Could not write to tmp file");
    //                 goto cleanup_err;
    //             }
    //         }
    //     }
    //     else
    //     {
    //         // Try again in the next loop execution
    //     }
    // }

    // // Send the file's content back
    // tmp_file_rd_fd = open(filename, O_RDONLY);
    // if (-1 == tmp_file_rd_fd)
    // {
    //     syslog(LOG_ERR, "Could not open tmp file for reading");
    // }

    // // Write stream content comning after the newline to the file
    // if (-1 == write(tmp_file_wr_fd, tmp_buffer, strlen(tmp_buffer)))
    // {
    //     syslog(LOG_ERR, "Could not write to tmp file");
    //     goto cleanup_err;
    // }

    // Clean-up for next packet
    memset((void*)buffer, 0, sizeof(char) * BUFFER_SIZE);

    // Everything went fine
    closelog();
    close(cfd);
    close(tmp_file_wr_fd);
    close(tmp_file_rd_fd);
    // remove(filename);
    return 0;

cleanup_err:
    printf("Cleaning up and returning -1\n");
    closelog();
    close(cfd);
    close(tmp_file_wr_fd);
    close(tmp_file_rd_fd);
    // remove(filename);
    return -1;
}
