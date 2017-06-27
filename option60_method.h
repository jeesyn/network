#ifndef OPTION60_METHOD_H
#define OPTION60_METHOD_H

struct option60_input {
		int* interp;
		long* longp;
		char* str1;
		char* str2;
};

int generate_option60(struct option60_input* arg, char* outbuf);

#endif
