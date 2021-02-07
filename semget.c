#include "comm.h"

static int commsemset(int nums, int flags)
{
    key_t key = ftok(PATHNAME, PROJ_ID);
    if (key < 0)
    {
        printf("ftok error\n");
        return -1;
    }
    int semid = semget(key, nums, flags);
    if (semid < 0)
    {
        printf("semget error\n");
        return -2;
    }
    return semid;
}
int createsemset(int nums)
{
    return commsemset(nums, IPC_CREAT | IPC_EXCL | 0666);
}
int getsemset(int nums)
{
    return commsemset(nums, IPC_CREAT);
}
int initsem(int semid, int nums, int initval)
{
    union semun _un;
    _un.val = initval;
    if (semctl(semid, nums, SETVAL, _un) < 0)
    {
        printf("semctl error\n");
        return -1;
    }
    return 0;
}
static int commPV(int semid, int who, int op)
{
    struct sembuf _buf;
    _buf.sem_num = who;
    _buf.sem_op = op;
    _buf.sem_flg = 0;
    if (semop(semid, &_buf, 1) < 0)
    {
        printf("semop error\n");
        return -1;
    }
    return 0;
}
int P(int semid, int who)
{
    return commPV(semid, who, -1);
}
int V(int semid, int who)
{
    return commPV(semid, who, 1);
}
int destroysemset(int semid)
{
    if (semctl(semid, 0, IPC_RMID) < 0)
    {
        printf("semctl error");
        return -1;
    }
}
