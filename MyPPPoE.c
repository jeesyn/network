#include "MyPPPoE.h"
#include "itemlist.h"
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#include <android/log.h>
#define syslog(prio, fmt...) \
    __android_log_print(prio, "PPPOE", fmt)
#endif


pthread_mutex_t in_mutex, out_mutex ;
pthread_cond_t inpthread_cond, outpthread_cond;

#define RW_LOCK(mutex)\
    do{\
        pthread_mutex_lock(&mutex);\
    }while(0);

#define RW_UNLOCK(mutex)\
    do{\
        pthread_mutex_unlock(&mutex);\
    }while(0);

static long long MPacketIndex = 0;

struct itemlist inMpacketList;
struct itemlist outMpacketList;
struct itemlist freeMpacketList;

void rw_mutex_init(void)
{
    pthread_mutex_init(&in_mutex,NULL);
    pthread_mutex_init(&out_mutex,NULL);
}
void cond_init(void)
{
    pthread_cond_init(&inpthread_cond, NULL);
    pthread_cond_init(&outpthread_cond, NULL);
}

void mpacket_list_init(void)
{
    inMpacketList.max_items = 250;
    inMpacketList.item_ext_buf_size = 0;
    inMpacketList.muti_threads_access = 1;
    inMpacketList.reject_same_item_data = 0;
    itemlist_init(&inMpacketList);

    outMpacketList.max_items = 250;
    outMpacketList.item_ext_buf_size = 0;
    outMpacketList.muti_threads_access = 1;
    outMpacketList.reject_same_item_data = 0;
    itemlist_init(&outMpacketList);

    freeMpacketList.max_items = 250;
    freeMpacketList.item_ext_buf_size = 0;
    freeMpacketList.muti_threads_access = 1;
    freeMpacketList.reject_same_item_data = 0;
    itemlist_init(&freeMpacketList);
}
static long long getMPacketIndex()
{
    return  MPacketIndex++;
}

static void log_MPacket(MyPPPoEPacket* mpacket,char* tag)
{
    syslog(LOG_ERR, "%s: mpacket->index: %lld,mpacket->len:%d",tag,mpacket->index,mpacket->len);
}

void readMPacketFromEth(PPPoEConnection *conn, int sock, int clampMss)
{
    struct item* mpacketItem;
    MyPPPoEPacket* pmpacket;
    PPPoEPacket* ppacket;
    int len;
    int plen;
#ifdef USE_BPF
    int type;
#endif

    mpacketItem = itemlist_get_head(&freeMpacketList);
    if (mpacketItem == NULL)
        mpacketItem = item_alloc(0);
    if (mpacketItem == NULL) goto ERR;
    pmpacket = &(mpacketItem->mpacket);
    ppacket = &(pmpacket->packet);

    if (receivePacket(sock, ppacket, &len) < 0) {
    goto ERR;
    }

    /* Check length */
    if (ntohs(ppacket->length) + HDR_SIZE > (unsigned int)len) {
        syslog(LOG_ERR, "Bogus PPPoE length field (%u)",
           (unsigned int) ntohs(ppacket->length));
    goto ERR;
    }
#ifdef DEBUGGING_ENABLED
    if (conn->debugFile) {
    dumpPacket(conn->debugFile, ppacket, "RCVD");
    fprintf(conn->debugFile, "\n");
    fflush(conn->debugFile);
    }
#endif

#ifdef USE_BPF
    /* Make sure this is a session packet before processing further */
    type = etherType(ppacket);
    if (type == Eth_PPPOE_Discovery) {
    sessionDiscoveryPacket(ppacket);
    } else if (type != Eth_PPPOE_Session) {
    goto ERR;
    }
#endif

    /* Sanity check */
    if (ppacket->code != CODE_SESS) {
    syslog(LOG_ERR, "Unexpected packet code %d", (int) ppacket->code);
    goto ERR;
    }
    if (ppacket->ver != 1) {
    syslog(LOG_ERR, "Unexpected packet version %d", (int) ppacket->ver);
    goto ERR;
    }
    if (ppacket->type != 1) {
    syslog(LOG_ERR, "Unexpected packet type %d", (int) ppacket->type);
    goto ERR;
    }
    if (memcmp(ppacket->ethHdr.h_dest, conn->myEth, ETH_ALEN)) {
    goto ERR;
    }
    if (memcmp(ppacket->ethHdr.h_source, conn->peerEth, ETH_ALEN)) {
    /* Not for us -- must be another session.  This is not an error,
       so don't log anything.  */
    goto ERR;
    }
    if (ppacket->session != conn->session) {
    /* Not for us -- must be another session.  This is not an error,
       so don't log anything.  */
    goto ERR;
    }
    plen = ntohs(ppacket->length);
    if (plen + HDR_SIZE > (unsigned int)len) {
    syslog(LOG_ERR, "Bogus length field in session packet %d (%d)",
           (int) plen, (int) len);
    goto ERR;
    }

    /* Clamp MSS */
    if (clampMss) {
    clampMSS(ppacket, "incoming", clampMss);
    }

    pmpacket->index = getMPacketIndex();
    if(itemlist_add_tail(&inMpacketList,mpacketItem) < 0 )
        goto ERR;

    //log_MPacket(&mpacketItem->mpacket,"readMPacketFromEth");
    pthread_cond_signal(&inpthread_cond);
    return ;

    ERR:
        syslog(LOG_ERR, "readMPacketFromEth:ERR \n");

        if (itemlist_add_tail(&freeMpacketList,mpacketItem) < 0)
            item_free(mpacketItem);
        return;
}

static void processMPacket(MyPPPoEPacket* mpacket)
{
    PPPoEPacket* packet;
    int plen;
    int i;
    unsigned char *ptr = mpacket->pppBuf;
    unsigned char c;
    UINT16_t fcs;
    unsigned char header[2] = {FRAME_ADDR, FRAME_CTRL};
    unsigned char tail[2];

    packet = &mpacket->packet;
    plen = ntohs(packet->length);
    /* Compute FCS */
    fcs = pppFCS16(PPPINITFCS16, header, 2);
    fcs = pppFCS16(fcs, packet->payload, plen) ^ 0xffff;
    tail[0] = fcs & 0x00ff;
    tail[1] = (fcs >> 8) & 0x00ff;

    /* Build a buffer to send to PPP */
    *ptr++ = FRAME_FLAG;
    *ptr++ = FRAME_ADDR;
    *ptr++ = FRAME_ESC;
    *ptr++ = FRAME_CTRL ^ FRAME_ENC;

    for (i=0; i<plen; i++) {
	c = packet->payload[i];
	if (c == FRAME_FLAG || c == FRAME_ADDR || c == FRAME_ESC || c < 0x20) {
	    *ptr++ = FRAME_ESC;
	    *ptr++ = c ^ FRAME_ENC;
	} else {
	    *ptr++ = c;
	}
    }
    for (i=0; i<2; i++) {
	c = tail[i];
	if (c == FRAME_FLAG || c == FRAME_ADDR || c == FRAME_ESC || c < 0x20) {
	    *ptr++ = FRAME_ESC;
	    *ptr++ = c ^ FRAME_ENC;
	} else {
	    *ptr++ = c;
	}
    }
    *ptr++ = FRAME_FLAG;
    mpacket->len = ptr - mpacket->pppBuf;

}

static void writeMPacket(MyPPPoEPacket* mpacket)
{
    if (write(STDOUT_FILENO, mpacket->pppBuf, mpacket->len) < 0)
	    fatalSys("asyncReadFromEth: write");
}

void thread_ProcessPacket(unsigned long arg)
{
    struct item* mpacketItem;
    int thread_num = arg;
    while (1){
        mpacketItem = itemlist_get_head(&inMpacketList);
        if (mpacketItem == NULL) {
            pthread_mutex_lock(&in_mutex);
            pthread_cond_wait(&inpthread_cond, &in_mutex);
            pthread_mutex_unlock(&in_mutex);
            continue;
        }
        processMPacket(&mpacketItem->mpacket);
        //log_MPacket(&mpacketItem->mpacket,"thread_ProcessPacket");
        /*here we insert sorted by mpacketItem->mpacket->index,to make
        outMpacketList sorted form little to big*/
        if(itemlist_sorted_insert(&outMpacketList,mpacketItem) < 0 ){
            syslog(LOG_ERR, "thread_ProcessPacket:sorted_insert failed %d\n",thread_num);
            continue ;
        }

        pthread_cond_signal(&outpthread_cond);
     }
}

void thread_WritePacket()
{
    struct item* mpacketItem;
    long long next_index = 0;
    int retry_cnt = 0 ;
    while(1)
    {
        int wait;
        mpacketItem = itemlist_peek_head(&outMpacketList);
       if (mpacketItem == NULL) {
            wait  = 1;
        } else {
            wait = (mpacketItem->mpacket.index > next_index) && retry_cnt < 6;
        }
        if (wait) {
            pthread_mutex_lock(&out_mutex);
            pthread_cond_wait(&outpthread_cond, &out_mutex);
            pthread_mutex_unlock(&out_mutex);
            retry_cnt++;
            continue;
        }
        retry_cnt = 0;
        next_index++;
        mpacketItem = itemlist_get_head(&outMpacketList);
      //log_MPacket(&mpacketItem->mpacket,"thread_WritePacket");
        writeMPacket(&mpacketItem->mpacket);
        if (itemlist_add_tail(&freeMpacketList,mpacketItem) < 0)
            item_free(mpacketItem);
    }

}
