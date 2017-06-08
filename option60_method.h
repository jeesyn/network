#ifndef OPTION60_METHOD_H
#define OPTION60_METHOD_H

struct option60_input {
		int inter1;
		long long1;
		char* str1;
		char* str2;
		char* outbuf;
};

int generate_option60(struct option60_input* arg);

#endif
