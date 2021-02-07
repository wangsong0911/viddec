
 #ifndef __SEMGET_H
 #define __SEMGET_H
 #include<stdio.h>
 #include<sys/types.h>
 #include<sys/ipc.h>
 #include<sys/sem.h>

 #define PATHNAME "."
 #define PROJ_ID 0x4444                                                                                                    
 union semun{
     int val;
     struct semid_ds *buf;
     unsigned short *array;
     struct seminfo *_buf;
 };
 int createsemset(int nums);//创建sem
 int initsem(int semid,int nums,int initval);
 int getsemset(int nums);
 int P(int semid,int who);//申请资源
 int V(int semid,int who);//释放资源
 int destroysemset(int semid);//销毁资源

 #endif //__SEMGET_H
