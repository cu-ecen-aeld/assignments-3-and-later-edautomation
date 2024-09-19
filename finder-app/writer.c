#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
    openlog("writersyslog", 0, LOG_USER);

    int nargs = argc - 1;  // Ignore name of the program
    if (nargs != 2)
    {
        syslog(LOG_ERR, "Expected 2 arguments, got %i\n", nargs);
        printf("Expected 2 arguments, got %i\n", nargs);
        closelog();
        return 1;
    }

    char* filename = argv[1];
    int fd = creat(filename, 0644);
    if (fd == -1)
    {
        int error_nbr = errno;
        perror("Error creating file: ");
        syslog(LOG_ERR, "Could not create file.");
        printf("Error creating file. Errno = %i\n", error_nbr);
        closelog();
        return 1;
    }
    else
    {
        printf("Successfully created file: %s\n", filename);
        syslog(LOG_INFO, "Successfully created file: %s\n", filename);
    }

    char* text = argv[2];
    size_t len = strlen(text);
    int write_result = write(fd, text, len);
    if (write_result == -1)
    {
        int error_nbr = errno;
        perror("Error writing to file file: ");
        syslog(LOG_ERR, "Could not write to file %s", filename);
        printf("Error writing to file. Errno = %i\n", error_nbr);
        closelog();
    }
    close(fd);
    closelog();
    return 0;
}