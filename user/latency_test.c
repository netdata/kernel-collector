#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/uio.h>

int wite_to_file(char *filename)
{
    static char *text = { "Hello World!\n" };
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        return -1;
    }

    fprintf(fp, "%s", text);

    struct iovec iov;

    iov.iov_base = text;
    iov.iov_len = 13;

    writev(fileno(fp) , &iov, 1);

    fclose(fp);

    return 0;
}

int read_from_file(char *filename)
{
    char data[24];
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }

    fread(data, sizeof(char), 13,  fp);

    struct iovec iov;

    iov.iov_base = data;
    iov.iov_len = 13;
    readv(fileno(fp) , &iov, 1);

    fclose(fp);

    return 0;
}

void *test(void *ptr)
{
    char *filename = { "test_io_with_me.txt" };
    int i;
    for (i = 0; i < 10000 ; i++)
    {
        if (!wite_to_file(filename)) {
            if (read_from_file(filename)) {
                unlink(filename);
                break;
            }
            unlink(filename);
        } else {
            break;
        }
    }

    return NULL;
}

int main(int argc, char **argv)
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_t thread;

    int i ;

    for (i = 0; i < 1000 ; i++ )
    {
        if (pthread_create(&thread, &attr, test, NULL)) {
            return 1;
        }

        pthread_join(thread, NULL) ;
    }

    return 0;
}
