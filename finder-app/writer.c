#include <syslog.h>

int main(int argc, char* argv[])
{
    openlog("writersyslog", 0, LOG_USER);
    syslog(LOG_INFO, "Hello, syslog!");
    return 0;
}