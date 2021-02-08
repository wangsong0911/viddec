/*
 * Copyright (C) 2012 Texas Instruments
 * Author: Rob Clark <rob.clark@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "viddec3test.h"
#include "util.h"
#include "demux.h"
int FileFd;
#include "rtp.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>

static void* writeThread(void* arg);

static int SetPortReuse(SOCKET sock, int bReuse);
static int JoinGroup(SOCKET sock, const char* strGroupIP);

static frame_t* new_frame(uint8_t* p_frame_data, uint32_t i_size, uint32_t i_type, uint64_t i_stamp);
static int free_frame(frame_t** pp_frame);

static int add_frame(rtp_s* p_rtp, uint8_t* p_frame, uint32_t i_size, uint32_t i_type, uint64_t i_stamp, uint32_t i_flag);
static int clear_frame(rtp_s* p_rtp);
static int dump_frame(uint8_t* p_frame, uint32_t size);


/* Padding for width as per Codec Requirement (for h264) */
#define PADX  32
/* Padding for height as per Codec requirement (for h264)*/
#define PADY  24
/* omap drm device handle */
struct omap_device *dev = NULL;

int file;
int front = 0;
int behind = 1;
int left = 2;
int right = 3;

#define FRONT_PORT		1200
#define BEHIND_PORT		1201
#define LEFT_PORT		1202	
#define RIGHT_PORT      	1203

#define FRONT_IP		"192.168.1.10"
#define BEHIND_IP		"192.168.1.11"
#define LEFT_IP		"192.168.1.12"	
#define RIGHT_IP      	"192.168.1.13"


struct decoder {
	struct display *disp;
	struct demux *demux;
	struct buffer *framebuf;
	Engine_Handle engine;
	VIDDEC3_Handle codec;
	VIDDEC3_Params *params;
	VIDDEC3_DynamicParams *dynParams;
	VIDDEC3_Status *status;
	XDM2_BufDesc *inBufs;
	XDM2_BufDesc *outBufs;
	VIDDEC3_InArgs *inArgs;
	VIDDEC3_OutArgs *outArgs;
	XDAS_Int8 **outBuffer;
	XDAS_Int32 *outBufSizes;
	char *input;
	struct omap_bo *input_bo;
	int input_sz, uv_offset;
	int padded_width;
	int padded_height;
	int num_outBuf;
	size_t *outBuf_fd;
	suseconds_t tdisp;
};


struct informations {
	struct  _rtp_s rtp;
	struct decoder decoders;
};


/* When true, do not actually call VIDDEC3_process. For benchmarking. */
static int no_process = 0;
static int inloop = 0;

/* When true, loop at end of playback. */
static int loop = 0;

static void* video_recv_thread(struct informations * information)
{
	rtp_s* p_rtp = (rtp_s*) &(information->rtp);

	SOCKET sock = 0;
	SOCKADDR_IN addr;
	uint8_t p_recv_buf[4096];
	int i_recv_size = 0;
	uint8_t p_save_buf[4096];
	int i_time_out = 0;
	unsigned int value = 1;
	rtp_header_t rtp_header;

	if(p_rtp == NULL) {
		return NULL;
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));//端口复用

	memset((char *)&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(p_rtp->i_port);
	printf("addr.sin_port = %d\n", p_rtp->i_port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	//SetPortReuse(sock, 1);
	//bind
	if(bind(sock, (SOCKADDR*)&addr, sizeof(addr)) < 0) {
		printf("bind rtp socket error = %s\n", strerror(errno));
		return NULL;
	}
	struct timeval t;
	t.tv_sec = 0;
	t.tv_usec = 500000;
	p_rtp->i_nalu_ok_flag = 0;

	while(1) {
		if(1 == p_rtp->i_exit) {
			break;
		}
		memset(p_recv_buf, 0, sizeof(p_recv_buf));
		i_recv_size = recv(sock, p_recv_buf, sizeof (p_recv_buf), 0);
		//printf("cyj  %d p_rtp.i_port = %d\n",__LINE__,p_rtp->i_port);
		if(i_recv_size > 0) {
			i_time_out = 0;
			get_rtp_header(&rtp_header, p_recv_buf, i_recv_size);  //rtp header

			if(0x60 == rtp_header.i_pt) {// VIDEO
				p_rtp->i_video_time = rtp_header.i_timestamp; 
				int i_size = RtpTo264(p_recv_buf, i_recv_size, p_save_buf, &p_rtp->i_nalu_ok_flag, &p_rtp->i_last_pkt_num);
				if(0 == p_rtp->i_video_time_stamp) {
					p_rtp->i_video_time_stamp = rtp_header.i_timestamp;   // rtp timestamp
					p_rtp->i_video_frame_index = 0;
				}

				if(p_rtp->i_video_time_stamp != rtp_header.i_timestamp) {
					if(p_rtp->i_video_frame_index > 0) {
						if(-1 == p_rtp->i_nalu_ok_flag) {
							printf("%d \n", __LINE__);
							p_rtp->i_nalu_ok_flag = 0;
						}else {
							add_frame(p_rtp, p_rtp->p_video_frame, p_rtp->i_video_frame_index, 1, p_rtp->i_video_time, rtp_header.i_ssrc >> 24);
						}
					}
					p_rtp->i_video_frame_index = 0;
					p_rtp->i_video_time_stamp = rtp_header.i_timestamp;
					memcpy(p_rtp->p_video_frame+p_rtp->i_video_frame_index, p_save_buf, i_size);
					p_rtp->i_video_frame_index += i_size;
				}else {
					memcpy(p_rtp->p_video_frame+p_rtp->i_video_frame_index, p_save_buf, i_size);
					p_rtp->i_video_frame_index += i_size;
				}
			}
		}else {
			i_time_out += 500;
			if (i_time_out > 5000) {
				printf("rtp no data recv\n");
				i_time_out = 0;
			}
		}
	}
	close(sock);
	sock = -1;
	return NULL;
}

int get_rtp_header(rtp_header_t* p_header, uint8_t* p_buf, uint32_t i_size)
{
	int i_ret = 0;

	if (p_header == NULL || p_buf == NULL || i_size < 0)
	{
		i_ret = -1;
	}
	else
	{
		p_header->i_version = (p_buf[0] & 0xC0) >> 6;
		p_header->i_extend = (p_buf[0] & 0x10) >> 4;
		p_header->i_cc = (p_buf[0] & 0x0F);
		p_header->i_m_tag = (p_buf[1] & 0x80) >> 7;
		p_header->i_pt = (p_buf[1] & 0x7F);
		p_header->i_seq_num = (p_buf[2] << 8);
		p_header->i_seq_num += p_buf[3];
		p_header->i_timestamp = (p_buf[4] << 24);
		p_header->i_timestamp += (p_buf[5] << 16);
		p_header->i_timestamp += (p_buf[6] << 8);
		p_header->i_timestamp += p_buf[7];

		p_header->i_ssrc = (p_buf[8] << 24);
		p_header->i_ssrc += (p_buf[9] << 16);
		p_header->i_ssrc += (p_buf[10] << 8);
		p_header->i_ssrc += p_buf[11];

		i_ret = 12;
		return i_ret;
	}
	return i_ret;
}

//buffer:接收到的数据；recv_bytes数据长度
//int RtpTo264(unsigned char* buffer, int recv_bytes, unsigned char* save_buffer, int* pnNALUOkFlag, int* pnLastPkt)
int RtpTo264(unsigned char* buffer, int recv_bytes, char* save_buffer, uint32_t* pnNALUOkFlag, uint32_t* pnLastPkt)
{
	unsigned char FU_FLAG = 0;
	int save_len = 0;
	unsigned int nPkt = 0;
	nPkt = (unsigned int) (((buffer[2]) << 8) | (buffer[3]));

	if(recv_bytes < 13) {
		printf("%d recv_bytes < 13 \n",__LINE__);
		*pnNALUOkFlag = -1;
		return -1;
	}

	if(nPkt - (*pnLastPkt) > 1) {
		printf("rtp lose packet, nPkt = %u, last = %u\n", nPkt, *pnLastPkt);//掉包。
		*pnNALUOkFlag = -1;
	}
	if(nPkt < (*pnLastPkt)) {
		//跳变
		printf("rtp lose packet 2\n");
	}
	(*pnLastPkt) = nPkt;
	FU_FLAG = (buffer[12])&(0x1F); //第13个字节和0x1F相与

	memset(save_buffer, 0, sizeof (save_buffer));
	memcpy(&(save_buffer[0]), &(buffer[12]), recv_bytes-12); //第13字节是此NALU的头，14字节及以后是NALU的内容，一起保存
	save_len = recv_bytes-12; //减12字节的RTP头
	//*pnNALUOkFlag = 0; //一个NALU就是一包，下面再来的包就是下一个NALU的了
	return save_len; //save_buffer里面要保存多少字节的数据
}

int write_output(char *y, char *uv,struct informations * information)
{
	int sz = 0, n = 0, i;
	int fd;
	int orig_height = 800;
	int orig_width = 1280;
	int stride = 1408;

	rtp_s* p_rtp = (rtp_s*) &(information->rtp);
	if (p_rtp == NULL)
	{
		printf("ERROR!\n");
		return;
	}

	if(p_rtp->i_port == FRONT_PORT)
	{
		fd = open("front.yuv", O_WRONLY | O_CREAT | O_APPEND, 0644);
	}
	else if(p_rtp->i_port == BEHIND_PORT)
	{		
		fd = open("behind.yuv", O_WRONLY | O_CREAT | O_APPEND, 0644);
	}
	else if(p_rtp->i_port == LEFT_PORT)
	{
		fd = open("left.yuv", O_WRONLY | O_CREAT | O_APPEND, 0644);
	}
	else if(p_rtp->i_port == RIGHT_PORT)
	{
		fd = open("right.yuv", O_WRONLY | O_CREAT | O_APPEND, 0644);
	}


	for( i = 0; i < orig_height; i++ ) {
		char   *p = y;
		int     len = orig_width;

		while( len && ((n = write(fd, p, len)) > 0)) {
			sz  += n;
			p   += n;
			len -= n;
		}

		if( n < 0 ) {
			ERROR("couldn't write to output file: (%d)", errno);
			break;
		}
		y += stride;
	}

	if( n >= 0 ) {
		for( i = 0; i < orig_height / 2; i++ ) {
			char   *p = uv;
			int     len = orig_width;

			while( len && ((n = write(fd, p, len)) > 0)) {
				sz  += n;
				p   += n;
				len -= n;
			}

			if( n < 0 ) {
				ERROR("couldn't write to output file: (%d)", errno);
				break;
			}
			uv += stride;
		}
	}
}



	static int
decoder_process(struct informations * information, uint32_t i_frame_size, uint8_t* p_frame)
{
	struct decoder* decoder = (struct decoder*) &(information->decoders);

	XDM2_BufDesc *inBufs = decoder->inBufs;
	XDM2_BufDesc *outBufs = decoder->outBufs;
	VIDDEC3_InArgs *inArgs = decoder->inArgs;
	VIDDEC3_OutArgs *outArgs = decoder->outArgs;
	struct buffer *buf;
	int freeBufCount =0;
	uint32_t i, n;
	XDAS_Int32 err;
	int eof = 0; /* end of file flag */
	int test_num;
	char *dst0 = NULL, *dst1 = NULL;

	rtp_s* p_rtp = (rtp_s*) &(information->rtp);
	if(p_rtp == NULL) {
		printf("ERROR!\n");
		return;
	}

	/* demux; in loop mode, we can do two tries at the end of the stream. */
	for (i = 0; i < 2; i++) {
		//n = demux_read(decoder->demux, decoder->input, decoder->input_sz);
		memcpy(decoder->input, p_frame, i_frame_size);
		decoder->input_sz = i_frame_size;
		n = 	i_frame_size;
		if(n) {
			buf = disp_get_vid_buffer(decoder->disp);
			if (!buf) {
				ERROR("%p: fail: out of buffers", decoder);
				return -1;
			}
			inBufs->descs[0].bufSize.bytes = n;
			inArgs->numBytes = n;
			//DBG("%p: push: %d bytes (%p)", decoder, n, buf);
		}else {
			/* end of input.. do we need to flush? */
			MSG("%p: end of input", decoder);

			eof = 1; /* set the flag for end of file to 1 */
			/* Control call call with XDM_FLUSH command */
			err = VIDDEC3_control(decoder->codec, XDM_FLUSH,
					decoder->dynParams, decoder->status);
			inBufs->numBufs = 0;
			outBufs->numBufs = 0;
			inArgs->inputID = 0;
		}
		break;
	}

	/*set the parameters if it is not the end of file */
	if (!eof) {
		inArgs->inputID = (XDAS_Int32)buf;
		outBufs->descs[0].buf = buf->fd[0];
		outBufs->descs[1].buf = (buf->multiplanar) ?buf->fd[1]:(XDAS_Int8 *)((outBufs->descs[0].buf));


		if(buf->multiplanar){
			decoder->outBuf_fd[0] = buf->fd[0];
			decoder->outBuf_fd[1] = buf->fd[1];
			dce_buf_lock(2,decoder->outBuf_fd);
		}
		else{
			decoder->outBuf_fd[0] = buf->fd[0];
			dce_buf_lock(1,decoder->outBuf_fd);
		}
		decoder->outBufs->descs[0].bufSize.bytes =decoder->padded_width*decoder->padded_height;
		decoder->outBufs->descs[1].bufSize.bytes = decoder->padded_width* (decoder->padded_height/2);
	}

	//	do {
	if(no_process) {
		/* Do not process. This is for benchmarking. We need to "fake"
		 * the outArgs. */
		outArgs->outputID[0] = 0;
		outArgs->freeBufID[0] = 0;
		if(!eof) {
			outArgs->outputID[0] = buf;
			outArgs->freeBufID[0] = buf;
		}
		outArgs->outputID[1] = NULL;
		outArgs->freeBufID[1] = NULL;
		outArgs->outBufsInUseFlag = 0;
	}else {
		suseconds_t tproc;
		tproc = mark(NULL);

		err = VIDDEC3_process(decoder->codec, inBufs, outBufs, inArgs, outArgs);
		if(err) {
			//ERROR("p_rtp->i_port = %d %p: process returned error: %d  ", p_rtp->i_port, decoder, err);
			printf("line = %d p_rtp->i_port = %d %p: process returned error: %d \n ",__LINE__,  p_rtp->i_port, decoder, err);
			//ERROR("%p: extendedError: %08x \n", decoder, outArgs->extendedError);
			if(XDM_ISFATALERROR(outArgs->extendedError)||( err == DCE_EXDM_UNSUPPORTED )||( err == DCE_EIPC_CALL_FAIL )||( err == DCE_EINVALID_INPUT ))
				return -1;
		}else {
			//printf("VIDDEC3_process is ok  \n" );
		}
	}

	for(i=0; outArgs->outputID[i]; i++) {
		/* get the output buffer and write it to file */
		buf = (struct buffer *)outArgs->outputID[i];
		XDM_Rect   *r = &(outArgs->displayBufs.bufDesc[0].activeFrameRegion);

		int yoff  = (r->topLeft.y * decoder->padded_width) + r->topLeft.x;
		int uvoff = (r->topLeft.y * decoder->padded_width / 2) + r->topLeft.x;
		//dst0 = (char*)omap_bo_map(buf->bo[0]);
		//dst1 =  (char*)omap_bo_map(buf->bo[1]);
		if(1 == file) {
			write_output((char*)omap_bo_map(buf->bo[0])+yoff, (char*)omap_bo_map(buf->bo[1])+uvoff, information);
			//write_output(dst0+yoff, dst1+uvoff, information);
		}

		if(!no_process) {
			//		MSG("post buffer: %p   %d,%d %d,%d", buf,r->topLeft.x, r->topLeft.y,r->bottomRight.x, r->bottomRight.y);   //post buffer: 0x1f9b8   32,24 1312,824
			disp_post_vid_buffer(p_rtp->i_port,decoder->disp, buf,
					r->topLeft.x, r->topLeft.y,
					r->bottomRight.x - r->topLeft.x,
					r->bottomRight.y - r->topLeft.y);
		}
		disp_put_vid_buffer(decoder->disp, buf);

	}

	for(i=0; outArgs->freeBufID[i]; i++) {
		buf = (struct buffer *)outArgs->freeBufID[i];
		disp_put_vid_buffer(decoder->disp, buf);

		//DBG("%s, %s, %d\n", __FILE__, __func__, __LINE__);
		if(buf->multiplanar) {
			decoder->outBuf_fd[freeBufCount++] = buf->fd[0];
			decoder->outBuf_fd[freeBufCount++] = buf->fd[1];
		}else {
			decoder->outBuf_fd[freeBufCount++] = buf->fd[0];
		}
	}

	if(freeBufCount) {
		if(!eof)
			dce_buf_unlock(freeBufCount, decoder->outBuf_fd);
		freeBufCount =0;
	}
	if(outArgs->outBufsInUseFlag) {
		MSG("%p: TODO... outBufsInUseFlag", decoder); // XXX
	}
	//	} while ((err == 0) && eof && !no_process);
	return (inBufs->numBufs > 0) ? 0 : -1;
}

static void decoder_close(struct decoder *decoder)
{
	if(!decoder) return;
	/* free output buffers allocated by display */
	if(inloop < 2 && decoder->disp)
		disp_free_buffers(decoder->disp,decoder->num_outBuf);

	if (decoder->status)
		dce_free(decoder->status);
	if (decoder->params)
		dce_free(decoder->params);
	if (decoder->dynParams)
		dce_free(decoder->dynParams);
	if (decoder->inBufs) {
		dce_buf_unlock(1, &(decoder->inBufs->descs[0].buf));
		close(decoder->inBufs->descs[0].buf);
		dce_free(decoder->inBufs);
	}
	if (decoder->outBufs)
		dce_free(decoder->outBufs);
	if (decoder->inArgs)
		dce_free(decoder->inArgs);
	if (decoder->outArgs)
		dce_free(decoder->outArgs);
	if (decoder->codec)
		VIDDEC3_delete(decoder->codec);
	if (decoder->engine)
		Engine_close(decoder->engine);
	if (decoder->input_bo)
		omap_bo_del(decoder->input_bo);
	if (decoder->outBuf_fd)
		free(decoder->outBuf_fd);
	if(inloop < 2) {
		if (dev)
			dce_deinit(dev);
		//if (decoder->demux)          demux_deinit(decoder->demux);
		if (decoder->disp)
			disp_close(decoder->disp);
		if(decoder) free(decoder);
	}
} 


int threadCreate(THREAD* funcThread, void* param)
{
	pthread_attr_t attr;
	pthread_t Thrd;
	struct sched_param SchedParam;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
	sched_getparam(0, &SchedParam);
	SchedParam.sched_priority = sched_get_priority_max(SCHED_FIFO);
	pthread_attr_setschedparam(&attr, &SchedParam);

	int s = pthread_create(&Thrd, &attr, funcThread, param);
	if (s != 0) {
		printf("threadCreate failed.\n");
		//handle_error_en(s, "pthread_create");
	}

	return 0;
}

static void* decode_stream(struct informations * information)
{
	key_t key;
	int shmid;				//shmidRight,shmidFront,shmidBack;
	SHARED_BUF_T *space;	//spaceRight,*spaceFront,*spaceBack;
	rtp_s* p_rtp = (rtp_s*) &(information->rtp);
	//struct decoder* decoder = (struct decoder*) &(information->decoders);
	frame_t* pf = NULL;		//frame
	if (p_rtp == NULL) {
		printf("ERROR!\n");
		return;
	}
	//	int ret;
	printf("p_rtp->i_port = %d\n", p_rtp->i_port);
	//FILE* fileHandler = NULL;
	if(p_rtp->i_port == FRONT_PORT) {
		key = ftok("/home/root/", 4);
		//fileHandler = fopen("front.h264", "wb");
		printf("open front.h264 \n");
	}else if(p_rtp->i_port == BEHIND_PORT) {
		key = ftok("/home/root/", 5);
		//fileHandler = fopen("behind.h264", "wb");
		printf("open behind.h264 \n");
	}else if(p_rtp->i_port == LEFT_PORT) {
		key = ftok("/home/root/", 2);
		//fileHandler = fopen("left.h264", "wb");
		printf("open left.h264 \n");
	}else if(p_rtp->i_port == RIGHT_PORT) {
		key = ftok("/home/root/", 3);
		//fileHandler = fopen("right.h264", "wb");
		printf("open right.h264 \n");
	}
	shmid= shmget(key, imageSize.height*1.5*imageSize.width+sizeof(int), IPC_CREAT);
	space= (SHARED_BUF_T *)shmat(shmid, NULL, 0);
	while(1) {
		pthread_mutex_lock(&p_rtp->mutex);
		pthread_cond_wait(&p_rtp->cond, &p_rtp->mutex);

		//frame_t* pf = NULL;	//frame
		pf = p_rtp->p_frame_header;
		//printf("line = %d p_rtp->i_port = %d  p_rtp->i_buf_num = %d \n",__LINE__, p_rtp->i_port, p_rtp->i_buf_num);
		if (pf != NULL) {
			//size_t nwrote = fwrite(pf->p_frame, 1, pf->i_frame_size, fileHandler);
			while(space->flag) {
				usleep(1);
			}
			space->flag = 1;
			decoder_process(information, pf->i_frame_size, pf->p_frame);
			memcpy(space->buffer,pf->p_frame,pf->i_frame_size);
			space->flag = 0; 

			//clear frame.
			p_rtp->i_buf_num--;
			p_rtp->p_frame_header = pf->p_next;
			if (p_rtp->i_buf_num <= 0) {
				p_rtp->p_frame_buf = p_rtp->p_frame_header;
			}
		}

		while(p_rtp->i_buf_num>0) {
			pf = p_rtp->p_frame_header;
			printf("line=%d, p_rtp->i_port=%d, p_rtp->i_buf_num=%d\n", __LINE__, p_rtp->i_port, p_rtp->i_buf_num);
			if (NULL != pf) {
				//size_t nwrote = fwrite(pf->p_frame, 1, pf->i_frame_size, fileHandler);
				//clear frame.
				p_rtp->i_buf_num--;
				p_rtp->p_frame_header = pf->p_next;
				if(p_rtp->i_buf_num <= 0) {
					p_rtp->p_frame_buf = p_rtp->p_frame_header;
				}
			}
		}
		//free_frame(&pf);
		//pf = NULL;
		pthread_mutex_unlock(&p_rtp->mutex);
	}
	//decoder_close(decoder);
	//fclose(fileHandler);
}

static int clear_frame(rtp_s* p_rtp)
{
	frame_t* p_temp = NULL;
	pthread_mutex_lock(&p_rtp->mutex);

	while (p_rtp->p_frame_header != NULL)
	{
		p_temp = p_rtp->p_frame_header->p_next;
		free_frame(&p_rtp->p_frame_header);
		p_rtp->p_frame_header = p_temp;
	}
	p_rtp->p_frame_buf = NULL;
	p_rtp->p_frame_header = NULL;
	p_rtp->i_buf_num = 0;
	pthread_mutex_unlock(&p_rtp->mutex);
	return 0;
}


static int add_frame(rtp_s* p_rtp, uint8_t* p_frame, uint32_t i_size, uint32_t i_type, uint64_t i_stamp, uint32_t i_flag)
{

	//printf("add frame, i_type = %d, i_stamp = %u\n", i_type, i_stamp);
	if (p_rtp->i_buf_num > 10)
	{
		printf("rtp frame buf overlow, notice this\n");
	}
	else
	{
		pthread_mutex_lock(&p_rtp->mutex);

		//printf("line = %d p_rtp->i_buf_num = %d\n",__LINE__,p_rtp->i_buf_num);
		if (p_rtp->p_frame_buf == NULL)
		{
			p_rtp->p_frame_buf = new_frame(p_frame, i_size, i_type, i_stamp);
			p_rtp->p_frame_header = p_rtp->p_frame_buf;
			p_rtp->p_frame_buf->i_flag = i_flag;
		}
		else
		{
			frame_t* p_new = new_frame(p_frame, i_size, i_type, i_stamp);
			p_new->i_flag = i_flag;
			p_rtp->p_frame_buf->p_next = p_new;
			p_rtp->p_frame_buf = p_new;

			printf("%x, header = %x\n", p_rtp->p_frame_buf, p_rtp->p_frame_header);

		}
		if ((p_rtp->p_frame_buf->p_frame[3]&0x1F) != 1)
		{
			//printf("%x, %d\n", p_rtp->p_frame_buf->p_frame[3], i_size);
		}

		p_rtp->i_buf_num++;

		//printf("line = %d p_rtp->i_buf_num = %d\n",__LINE__,p_rtp->i_buf_num);
		pthread_cond_signal(&p_rtp->cond);
		pthread_mutex_unlock(&p_rtp->mutex);
	}
	return 0;
}

static int free_frame(frame_t** pp_frame)
{
	if ((*pp_frame) != NULL)
	{
		free((*pp_frame));
		(*pp_frame) = NULL;
	}
	return 0;
}

static frame_t* new_frame(uint8_t* p_frame_data, uint32_t i_size, uint32_t i_type, uint64_t i_stamp)
{
	int i_ret = 0;
	frame_t* p_new = NULL;
	if (p_frame_data == NULL || i_size <= 0)
	{
		i_ret = -1;
	}
	else
	{
		p_new = malloc(i_size + sizeof (frame_t));
		if (p_new == NULL)
		{
			printf("malloc rtp frame error\n");
			i_ret = -1;
		}
		else
		{
			p_new->p_frame = ((uint8_t*) p_new) + sizeof (frame_t);

			p_new->i_frame_size = i_size;
			p_new->i_type = i_type;
			p_new->i_time_stamp = i_stamp;
			p_new->p_next = NULL;
			memcpy(p_new->p_frame, p_frame_data, i_size);
		}
	}

	if (i_ret < 0)
	{
		return NULL;
	}
	else
	{
		return p_new;
	}
}

static int dump_frame(uint8_t* p_frame, uint32_t size)
{
	printf("*********************************************************:%u\n", size);
	if(p_frame != NULL && size >0)
	{
		uint32_t i=0;
		for(; i<size; i++)
		{
			printf("%x ", p_frame[i]);

			if((i+1)%32 == 0)
			{
				printf("\n");
			}
		}
	}
	printf("\n");
}


static struct decoder *decoder_open(int argc, char **argv, struct decoder *decoder)
{
	char *infile = NULL;
	int i;
	static int width, height, padded_width, padded_height;
	Engine_Error ec;
	XDAS_Int32 err;

	if(inloop < 2) {
		//decoder = calloc(1, sizeof(*decoder));
		if (!decoder)
			return NULL;

		MSG("%p: Opening Display...\n", decoder);
		decoder->disp = disp_open(argc, argv);

		width = 1280;
		height = 800;
		/* calculate output buffer parameters: */
		width  = ALIGN2(width, 4);        //round up to macroblocks
		height = ALIGN2(height, 4);       //round up to macroblocks

		padded_width = ALIGN2(width+(2*PADX), 7);
		padded_height = height+4*PADY;

		decoder->num_outBuf = MIN(16, 32768/((width/16)*(height/16)))+3;
		decoder->padded_width = padded_width;
		decoder->padded_height = padded_height;
		MSG("%p: padded_width=%d, padded_height=%d, num_buffers=%d",
				decoder, padded_width, padded_height, decoder->num_outBuf);

		dce_set_fd(decoder->disp->fd);
		dev = dce_init();
		if(dev == NULL) {
			ERROR("%p: dce init failed", dev);
			goto fail;
		}
		decoder->framebuf = disp_get_fb(decoder->disp);
		if(!disp_get_vid_buffers(decoder->disp, decoder->num_outBuf, 
				FOURCC_STR("NV12"), decoder->padded_width, decoder->padded_height)) {
			ERROR("%p: could not allocate buffers", decoder);
			goto fail;
		}
		if(inloop)
			inloop = 2; /*Don't bother about looping if not asked to*/
	}

	if(!decoder->disp->multiplanar) {
		decoder->uv_offset = padded_width*padded_height;
		decoder->outBuf_fd = malloc(sizeof(int)*decoder->num_outBuf);
		MSG("%p: uv_offset=%d", decoder, decoder->uv_offset);
	}else {
		decoder->outBuf_fd = malloc(sizeof(int)*(decoder->num_outBuf*2));
	}

	decoder->input_sz = width * height;
	decoder->input_bo = omap_bo_new(decoder->disp->dev, decoder->input_sz, OMAP_BO_WC);
	decoder->input = omap_bo_map(decoder->input_bo);

	MSG("%p: Opening Engine..", decoder);
	decoder->engine = Engine_open("ivahd_vidsvr", NULL, &ec);
	if (!decoder->engine) {
		ERROR("%p: could not open engine", decoder);
		goto fail;
	}

	decoder->params = dce_alloc(sizeof(IVIDDEC3_Params));
	decoder->params->size = sizeof(IVIDDEC3_Params);

	decoder->params->maxWidth         = width;
	decoder->params->maxHeight        = height;
	decoder->params->maxFrameRate     = 30000;
	decoder->params->maxBitRate       = 10000000;
	decoder->params->dataEndianness   = XDM_BYTE;
	decoder->params->forceChromaFormat= XDM_YUV_420SP;
	decoder->params->operatingMode    = IVIDEO_DECODE_ONLY;
	decoder->params->displayDelay     = IVIDDEC3_DISPLAY_DELAY_AUTO;
	decoder->params->displayBufsMode  = IVIDDEC3_DISPLAYBUFS_EMBEDDED;
	MSG("displayBufsMode: %d", decoder->params->displayBufsMode);
	decoder->params->inputDataMode    = IVIDEO_ENTIREFRAME;
	decoder->params->metadataType[0]  = IVIDEO_METADATAPLANE_NONE;
	decoder->params->metadataType[1]  = IVIDEO_METADATAPLANE_NONE;
	decoder->params->metadataType[2]  = IVIDEO_METADATAPLANE_NONE;
	decoder->params->numInputDataUnits= 0;
	decoder->params->outputDataMode   = IVIDEO_ENTIREFRAME;
	decoder->params->numOutputDataUnits = 0;
	decoder->params->errorInfoMode    = IVIDEO_ERRORINFO_OFF;

	MSG("decoder->params->maxWidth = %d, decoder->params->maxHeight = %d./n", decoder->params->maxWidth, decoder->params->maxHeight);

	decoder->codec = VIDDEC3_create(decoder->engine,
			"ivahd_h264dec", decoder->params);

	if (!decoder->codec) {
		ERROR("%p: could not create codec", decoder);
		goto fail;
	}

	decoder->dynParams = dce_alloc(sizeof(IVIDDEC3_DynamicParams));
	decoder->dynParams->size = sizeof(IVIDDEC3_DynamicParams);
	decoder->dynParams->decodeHeader  = XDM_DECODE_AU;

	/*Not Supported: Set default*/
	decoder->dynParams->displayWidth  = 0;
	decoder->dynParams->frameSkipMode = IVIDEO_NO_SKIP;
	decoder->dynParams->newFrameFlag  = XDAS_TRUE;

	decoder->status = dce_alloc(sizeof(IVIDDEC3_Status));
	decoder->status->size = sizeof(IVIDDEC3_Status);

	err = VIDDEC3_control(decoder->codec, XDM_SETPARAMS, decoder->dynParams, decoder->status);
	if (err) {
		ERROR("%p: fail: %d", decoder, err);
		goto fail;
	}

	/* not entirely sure why we need to call this here.. just copying omx.. */
	err = VIDDEC3_control(decoder->codec, XDM_GETBUFINFO, decoder->dynParams, decoder->status);
	if(err) {
		ERROR("%p: fail: %d", decoder, err);
		goto fail;
	}

	decoder->inBufs = dce_alloc(sizeof(XDM2_BufDesc));
	decoder->inBufs->numBufs = 1;
	decoder->inBufs->descs[0].buf =	(XDAS_Int8 *)omap_bo_dmabuf(decoder->input_bo);
	dce_buf_lock(1, &(decoder->inBufs->descs[0].buf));
	decoder->inBufs->descs[0].bufSize.bytes = omap_bo_size(decoder->input_bo);
	decoder->inBufs->descs[0].memType = XDM_MEMTYPE_RAW;

	decoder->outBufs = dce_alloc(sizeof(XDM2_BufDesc));
	decoder->outBufs->numBufs = 2;
	decoder->outBufs->descs[0].memType = XDM_MEMTYPE_RAW;
	decoder->outBufs->descs[1].memType = XDM_MEMTYPE_RAW;

	decoder->inArgs = dce_alloc(sizeof(IVIDDEC3_InArgs));
	decoder->inArgs->size = sizeof(IVIDDEC3_InArgs);

	decoder->outArgs = dce_alloc(sizeof(IVIDDEC3_OutArgs));
	decoder->outArgs->size = sizeof(IVIDDEC3_OutArgs);

	decoder->tdisp = mark(NULL);
	return decoder;

fail:
	if(inloop) inloop = 1; /*Error case: delete everything*/
	if(decoder)
		decoder_close(decoder);
	return NULL;
}

static struct information *information_init(int i)
{
	static struct informations *information = NULL;
	information = calloc(1, sizeof(*information));
	if (!information)
		return NULL;

	if(i == front) {
		information->rtp.i_port = FRONT_PORT;
		strcpy(information->rtp.p_ip, FRONT_IP);
	}else if(i == behind) {
		information->rtp.i_port = BEHIND_PORT;
		strcpy(information->rtp.p_ip, BEHIND_IP);
	}else if(i == left) {
		information->rtp.i_port = LEFT_PORT;
		strcpy(information->rtp.p_ip, LEFT_IP);
	}else if(i == right) {
		information->rtp.i_port = RIGHT_PORT;
		strcpy(information->rtp.p_ip, RIGHT_IP);
	}
	information->rtp.i_video_frame_index = 0;

	information->rtp.p_video_frame = (uint8_t*) malloc(MAX_VIDEO_FRAME_SIZE);

	information->rtp.i_nalu_ok_flag = 0;
	information->rtp.i_last_pkt_num = 0;
	information->rtp.i_aui_last_pkt_num = 0;

	information->rtp.i_buf_num = 0;
	information->rtp.p_frame_buf = NULL;
	information->rtp.p_frame_header = NULL;

	information->rtp.i_video_time_stamp = 0;

	information->rtp.i_exit = 0;

	pthread_mutex_init(&information->rtp.mutex, NULL);

	information->rtp.p_opaque = NULL;

	information->rtp.i_video_time = 0;
	information->rtp.i_seq_num = 0;

	return information;
}

int main(int argc, char **argv)
{
	int i, first=0, ndecoders=0;

	struct informations *information[4] = {};

	rtp_s input;
	char ip[40] = "255.255.255.255";

	MSG("line=%d, argc=%d.\n", __LINE__, argc);

	ndecoders = 4;
	for(i=0; i<ndecoders; i++) {
		//printf("%d \n", __LINE__);
		information[i] = information_init(i);
		
		decoder_open(argc, &argv[first], &(information[i]->decoders));
		threadCreate(video_recv_thread, information[i]);	// read rtp
		threadCreate(decode_stream, information[i]);		//decoders
	}
	while(1) {
		sleep(10);
	}

	return 0;
}
