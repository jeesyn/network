#ifndef _MYPPPOE_H_
#define _MYPPPOE_H_

#include "pppoe.h"

typedef struct MyPPPoEPacketStruct{
    PPPoEPacket packet;
    long long index;
    unsigned int len;
    unsigned char pppBuf[4096];
} MyPPPoEPacket;

void rw_mutex_init(void);
void cond_init(void);
void mpacket_list_init(void);

void readMPacketFromEth(PPPoEConnection *conn, int sock, int clampMss);

void thread_ProcessPacket(unsigned long arg);
void thread_WritePacket();

#endif
