/*
 * dhcpcd - option60 method
 * Copyright (c) 2017 Jingsong.Liu <jingsong.liu@amlogic.com>
 * All rights reserved

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include "common.h"
#include "hs_digest.h"
#include "stb_3des.h"
#include "option60_method.h"
#ifdef ANDROID
#include <cutils/properties.h>
#endif

#define PROJECT_TYPE 	"sys.proj.type"
#define PROJECT_TENDER	"sys.proj.tender.type"

struct option60_method {
		char* operator;
		char* location;
		int(*algorithms)(void*, char* outbuf);
};

/* common
 * O = 1
 * R = random
 * TS = timestamp
 * KEY = md5(R + passwd + TS)
 * context = 3des_enrypt(R + user + TS)
 * option60 = O + R + TS + KEY + context
 */
static int generate_option60_common(void* arg, char* outbuf)
{
	struct option60_input* opi = (struct option60_input*)arg;
	const char *user = opi->str1;
	const char *passwd = opi->str2;

	int i;
	//use O=1 to describe this algorithms.
	int _O = 1;
	unsigned char timestamp[9] = {0};
	unsigned char random_number[9] = {0};
	long long ts = 0;
	long long rd = 0;
	unsigned char context[25] = {0};
	unsigned char *ptr;
	char ciphertext[24] = {0};
	unsigned char md5text[129] = {0};
	unsigned char md5out[17]={0};
	int len;
	int md5len = 0;
	int handle;
	int outbuf_len = 0;

	syslog(LOG_DEBUG, "generate option60 method: %s", __FUNCTION__);
	syslog(LOG_DEBUG, "user:%s,passwd:%s\n",user,passwd);
	if((NULL == user)||(NULL == passwd))
	{
		strncpy(outbuf,"iTV",3);
		return strlen(outbuf);
	}
	rd = (long long)random();
	ptr = (unsigned char *)&rd;
	for(i=0;i<8;i++)
	{
		random_number[7-i] = *ptr;
		ptr++;
	}
	ts = (long long)time(NULL);
	ptr = (unsigned char *)&ts;
	for(i=0;i<8;i++)
	{
		timestamp[7-i] = *ptr;
		ptr++;
	}

	//context = 3des_enrypt(R + user + TS)
	memset(ciphertext,0,sizeof(ciphertext));
	memcpy(ciphertext,random_number,8);
	memcpy(ciphertext+8,timestamp,8);
	len = HS_3des_encrypt(ciphertext,(unsigned char*)user,context);

	//KEY = md5(R + passwd + TS)
	memset(md5text,0,sizeof(md5text));
	memcpy(md5text,random_number,8);
	md5len = 8;
	memcpy(md5text+md5len,passwd,strlen(passwd));
	md5len +=strlen(passwd);
	memcpy(md5text+md5len,timestamp,8);
	md5len += 8;
	handle = STB_digest_init(STB_DIGEST_MD5);
	STB_digest_update(handle,md5text,md5len);
	STB_digest_final(handle, md5out, 16);

	//opption60 = O + R + TS + KEY + context
	memset(outbuf,_O,1);
	outbuf_len +=1;
	memcpy(outbuf+outbuf_len,random_number,8);
	outbuf_len +=8;
	memcpy(outbuf+outbuf_len,timestamp,8);
	outbuf_len += 8;
	memcpy(outbuf+outbuf_len,md5out,16);
	outbuf_len += 16;
	memcpy(outbuf+outbuf_len,context,len);
	outbuf_len += len;

	return outbuf_len;
}

/* zhejiang telecom
 * O = 100
 * R = random
 * TS = timestamp
 * KEY = md5(R + passwd + TS)
 * option60 = O + R + TS + KEY + user
 */
static int generate_option60_telecom_zhejiang(void * arg, char* outbuf)
{
	struct option60_input * opi = (struct option60_input*)arg;
	const char *user = opi->str1;
	const char *passwd = opi->str2;

	int i;
	unsigned char timestamp[9] = {0};
	unsigned char random_number[9] = {0};
	long long ts = 0;
	long long rd = 0;
	unsigned char *ptr;
	unsigned char ciphertext[24] = {0};
	unsigned char md5text[129] = {0};
	unsigned char md5out[17]={0};
	int len;
	int md5len = 0;
	int handle;
	int outbuf_len = 0;
	//zhejiang telecom describe O=100 for this algorithms.
	int _O = 100;

	syslog(LOG_DEBUG, "generate option60 method: %s", __FUNCTION__);
	syslog(LOG_DEBUG, "user:%s,passwd:%s\n",user,passwd);
	if((NULL == user)||(NULL == passwd))
	{
		strncpy(outbuf,"iTV",3);
		return strlen(outbuf);
	}
	rd = (long long)random();
	ptr = (unsigned char *)&rd;
	for(i=0;i<8;i++)
	{
		random_number[7-i] = *ptr;
		ptr++;
	}
	ts = (long long)time(NULL);
	ptr = (unsigned char *)&ts;
	for(i=0;i<8;i++)
	{
		timestamp[7-i] = *ptr;
		ptr++;
	}

	//KEY = md5(R + passwd + TS)
	memset(md5text,0,sizeof(md5text));
	memcpy(md5text,random_number,8);
	md5len = 8;
	memcpy(md5text+md5len,passwd,strlen(passwd));
	md5len +=strlen(passwd);
	memcpy(md5text+md5len,timestamp,8);
	md5len += 8;

	handle = STB_digest_init(STB_DIGEST_MD5);
	STB_digest_update(handle,md5text,md5len);
	STB_digest_final(handle, md5out, 16);

	//opption60 = O + R + TS + KEY + user
	memset(outbuf,_O,1);
	outbuf_len +=1;
	memcpy(outbuf+outbuf_len,random_number,8);
	outbuf_len +=8;
	memcpy(outbuf+outbuf_len,timestamp,8);
	outbuf_len += 8;
	memcpy(outbuf+outbuf_len,md5out,16);
	outbuf_len += 16;
	memcpy(outbuf+outbuf_len,user,strlen(user));
	outbuf_len += strlen(user);

	return outbuf_len;
}

static int buf2hexstr(char* inbuf, char* outbuf, int len)
{
	//translate inbuf[len] to hexdecimal string[2*len]
	char * CODE = "0123456789ABCDEF";
	int i =0;
	for ( i = 0; i< len; i++) {
		outbuf[i*2] = CODE[inbuf[i]/16];
		outbuf[(i*2)+1] = CODE[inbuf[i]%16];
	}
	outbuf[i*2] = '\0';
    return i;
}

/* liaoning unicom
 * key = "LUIOITDCNNCMPVHP"
 * option60 = sha-1(xid + key)
 */
static int generate_option60_unicom_liaoning(void* arg, char* outbuf)
{
	struct option60_input * opi = (struct option60_input*)arg;
	long *xid = opi->longp;
	const char *key = "LUIOITDCNNCMPVHP";
	unsigned char sha1text[129] = {0};
	char xidtext[11]={0};
	char sha1buf[20];
	unsigned int sha1len = 0;
	int handle;

	//translate xid to network byte order (big endian).
	long xid_net = htonl(*xid);
	syslog(LOG_DEBUG, "generate option60 method: %s", __FUNCTION__);
	syslog(LOG_DEBUG, "xid:%lu(0x%lx); xid_net:%lu(0x%lx)",*xid, *xid, xid_net, xid_net);
	if(0 == *xid)
	{
		syslog(LOG_ERR, "error xid ");
		return -1;
	}
	snprintf(xidtext, sizeof(xidtext), "%lu",xid_net);

	//option60 = sha-1(xid + key)
	memset(sha1text,0,sizeof(sha1text));
	memcpy(sha1text,xidtext,strlen(xidtext));
	sha1len = strlen(xidtext);
	memcpy(sha1text+sha1len,key,strlen(key));
	sha1len += strlen(key);

	handle = STB_digest_init(STB_DIGEST_SHA1);
	STB_digest_update(handle,sha1text,sha1len);
	STB_digest_final(handle, outbuf, 20);

#ifdef OPT60_DBG
	char hexstr[41]={0};
	buf2hexstr(outbuf, hexstr,20);
	syslog(LOG_DEBUG, "Value : %s", hexstr);
#endif

	return 20;
}

/* If you wanna add your manufacture supported ,please fill the table in format:
 * {operator name, location name, generate option60 method},
 * it should be insterted befor NULL row.
 * the name your method should name as generate_option60_operator_location
 */
#define SIZE_OF_MANUFACTURE		128
static struct option60_method option60_method_table[SIZE_OF_MANUFACTURE] = {
	{"default",	"default",	generate_option60_common},  //for common method
	{"telecom", "zhejiang", generate_option60_telecom_zhejiang},
	{"unicom",  "liaoning", generate_option60_unicom_liaoning},
	{NULL,  NULL, NULL},
};

/* Get method of generate option60 according operator and location.
 * @param operator: operator name, such as mobile , unicom, telecom
 * @param location: local province such as shandong, sichuan
 * @return option60_method
 */
static struct option60_method* get_option60_method(const char* operator, const char* location)
{

	int i = 0;
	while(i < SIZE_OF_MANUFACTURE) {
		if (option60_method_table[i].operator == NULL ||
				option60_method_table[i].location == NULL)
			break;
		if(!strcmp(operator, option60_method_table[i].operator)
				&& !strcmp(location, option60_method_table[i].location)) {
			return (struct option60_method*)&option60_method_table[i];
		}
		i++;
	}
	return (struct option60_method*)&option60_method_table[0];
}

/* Generate option60 for different operator int different location.
 * @param: arg: arguments is carried with struct option60_input, according to different
 * 		   operator-locations,it carried different args, but mostly is username and
 * 		   passowrd.
 * @param: outbuf:	the output buffer of generated option 60.
 * @return: length of option 60.
 */
int generate_option60(struct option60_input* arg, char* outbuf)
{
	struct option60_method* mmethod;
	char operator[PROPERTY_VALUE_MAX] = {0};
	char location[PROPERTY_VALUE_MAX] = {0};
	property_get(PROJECT_TYPE, operator, "");
	property_get(PROJECT_TENDER, location, "");
	syslog(LOG_INFO, "Operator-Location: %s-%s\n",operator, location);

	mmethod = get_option60_method(operator,location);
	return mmethod->algorithms((void*)arg, outbuf);
}
