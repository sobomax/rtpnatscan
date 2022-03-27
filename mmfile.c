#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "mmfile.h"

#define MMTSIZE 16
#define MFDSIZE 128

struct mfile {
    char path[PATH_MAX + 1];
    void *fdata;
    off_t fsize;
};

struct mfd {
    const struct mfile *mmp;
    off_t pos;
};

static struct mfile mmtable[MMTSIZE];
static struct mfd mftable[MFDSIZE];
static pthread_mutex_t mmlock;

static const struct mfile *
mmopen(const char *path, int flags)
{
    int mdi, fd;
    struct stat s;
    void *fdata;

    for (mdi = 0; mdi < MMTSIZE; mdi++) {
        if (mmtable[mdi].fdata == NULL)
            break;
        if (strcmp(mmtable[mdi].path, path) == 0)
            goto gotres;
    }
    if (mdi == MMTSIZE)
        abort();
    fd = open(path, flags);
    if (fd < 0)
        goto e0;
    if (fstat(fd, &s) < 0)
        goto e1;
    fdata = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (fdata == MAP_FAILED)
        goto e1;
    mmtable[mdi].fdata = fdata;
    mmtable[mdi].fsize = s.st_size;
    strcpy(mmtable[mdi].path, path);
gotres:
    return (&mmtable[mdi]);
e1:
    close(fd);
e0:
    return (NULL);
}

int
mopen(const char *path, int flags)
{
    int fdi;

    if (flags != O_RDONLY)
        abort();
    pthread_mutex_lock(&mmlock);
    for (fdi = 0; fdi < MFDSIZE; fdi++) {
        if (mftable[fdi].mmp == NULL)
            break;
    }
    if (fdi == MFDSIZE)
        abort();
    mftable[fdi].mmp = mmopen(path, flags);
    if (mftable[fdi].mmp == NULL) {
        pthread_mutex_unlock(&mmlock);
        return (-1);
    }
    pthread_mutex_unlock(&mmlock);
    return (fdi);
}

ssize_t
mread(int fdi, void *buf, size_t nbytes)
{
    struct mfd *mp;
    ssize_t rval;

    mp = &mftable[fdi];
    if (mp->mmp->fsize - mp->pos < nbytes)
        nbytes = mp->mmp->fsize - mp->pos;
    if (nbytes > 0) {
        memcpy(buf, (char *)mp->mmp->fdata + mp->pos, nbytes);
        mp->pos += nbytes;
    }
    return (nbytes);
}

int
mclose(int fdi)
{
    struct mfd *mp;

    pthread_mutex_lock(&mmlock);
    mp = &mftable[fdi];
    memset(mp, '\0', sizeof(struct mfd));
    pthread_mutex_unlock(&mmlock);
    return (0);
}

int
minit(void)
{

    if (pthread_mutex_init(&mmlock, NULL) != 0) {
        return (-1);
    }
    return (0);
}
