#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
    openlog("aesdsocketsyslog", 0, LOG_USER);

    closelog();
    return 0;
}