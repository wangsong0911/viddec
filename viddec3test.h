#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libdce.h>
#include <xf86drm.h>
#include <omap_drm.h>
#include <omap_drmif.h>

#include <pthread.h>

typedef struct 
{
	int flag;
	char *buffer;
}SHARED_BUF_T;
