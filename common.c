#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <string.h>

#define BUFSIZE 768

typedef unsigned char uchar;
typedef unsigned int uint;
typedef struct{
	uchar *dat;
	size_t len;
} b64;

extern uint table[PHASE+1][256][256];
extern int ptt, socks5;
struct termios term;

int ptt, ssh, online=0, atime;
uint buildtable(uint, uchar [], int);
uchar *trim(char []);
void say(char []);
void echooff(void);
void echoon(void);
uchar * b64_encode(uchar *, ssize_t);
b64 b64_decode(uchar *);
uchar b64_ftable[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
uchar b64_btable[256];

uchar * b64_encode(uchar *str, ssize_t len){
	uchar * b64_result;
	ssize_t i, j, t, j1, j2, l;
	l=(t=len%3)?(len/3+1)*4:(len/3)*4;
	b64_result = (uchar *) malloc(l+1);
	if(b64_result==NULL){fprintf(stderr,"malloc failed.\n"); exit(1);}
	if(t) len-=3;
	for(i=0,j=0;j<len;){
		j2=(j1=j+1)+1;
		b64_result[i++] = b64_ftable[                       (str[j ]>>2)&0x3f ];
		b64_result[i++] = b64_ftable[((str[j ]&0x03)<<4) | ((str[j1]>>4)&0x0f)];
		b64_result[i++] = b64_ftable[((str[j1]&0x0f)<<2) | ((str[j2]>>6)&0x03)];
		b64_result[i++] = b64_ftable[ str[j2]&0x3f];
		j=j2+1;
	}
	switch(t){
		case 1:
			j2=(j1=j+1)+1;
			b64_result[i++] = b64_ftable[                       (str[j ]>>2)&0x3f ];
			b64_result[i++] = b64_ftable[((str[j ]&0x03)<<4)                      ];
			b64_result[i++] = '=';
			b64_result[i++] = '=';
		break;
		case 2:
			j2=(j1=j+1)+1;
			b64_result[i++] = b64_ftable[                       (str[j ]>>2)&0x3f ];
			b64_result[i++] = b64_ftable[((str[j ]&0x03)<<4) | ((str[j1]>>4)&0x0f)];
			b64_result[i++] = b64_ftable[((str[j1]&0x0f)<<2)                      ];
			b64_result[i++] = '=';
		break;
	}
	b64_result[i]=0;
	return b64_result;
}

b64 b64_decode(uchar *str){
	b64 ret;
	uchar * b64_result;
	uint r[4]={0,1,1,2};
	size_t i, j, b64_len, l=strlen(str), t, j1, j2, j3;
//	while(str[l-1]=='='){	//Comment for speed, but no longer standard-base64 compatible.
//		--l;
//	}
	t=l%4;
	l=(l/4)*3;
	b64_len=l+r[t];
	b64_result = (uchar *) malloc(b64_len);
	if(b64_result==NULL){fprintf(stderr,"malloc failed.\n"); exit(1);}
	for(i=0,j=0;i<l;){
		j3=(j2=(j1=j+1)+1)+1;
		b64_result[i++] = (b64_btable[str[j ]]<<2) | ((b64_btable[str[j1]]>>4)&0x03);
		b64_result[i++] = (b64_btable[str[j1]]<<4) | ((b64_btable[str[j2]]>>2)&0x0f);
		b64_result[i++] = (b64_btable[str[j2]]<<6) |  (b64_btable[str[j3]]);
		j=j3+1;
	}
	switch(t){
		case 1:
			j3=(j2=(j1=j+1)+1)+1;
			b64_result[i  ] = (b64_btable[str[j ]]<<2);
		break;
		case 2:
			j3=(j2=(j1=j+1)+1)+1;
			b64_result[i++] = (b64_btable[str[j ]]<<2) | ((b64_btable[str[j1]]>>4)&0x03);
			b64_result[i  ] = (b64_btable[str[j1]]<<4) ;
		break;
		case 3:
			j3=(j2=(j1=j+1)+1)+1;
			b64_result[i++] = (b64_btable[str[j ]]<<2) | ((b64_btable[str[j1]]>>4)&0x03);
			b64_result[i++] = (b64_btable[str[j1]]<<4) | ((b64_btable[str[j2]]>>2)&0x0f);
			b64_result[i  ] = (b64_btable[str[j2]]<<6) ;
		break;

	}
	ret.dat=b64_result;
	ret.len=b64_len;
	return ret;
}

void echooff(void){
	struct termios term2;
	tcgetattr(fileno(stdin), &term);
	term2 = term;
	term2.c_lflag &= ~ECHO;
	if(tcsetattr(fileno(stdin), TCSAFLUSH, &term2) != 0){
		fprintf(stderr, "Failed setting echo off.");
		exit(1);
	}
}

void echoon(void){
	tcsetattr(fileno(stdin), TCSANOW, &term);
}

uchar *trim(char str[]){
	uchar *ret=str;
	while(isspace(*ret)){
		++ret;
	}
	while(isspace(*(ret+strlen(ret)-1))){
		ret[strlen(ret)-1]=0;
	}
	return ret;
}

uint buildtable(uint st, uchar str[], int nst){
	static uint nextst=0;
	int final=0;
	uint t = 0, t2;
	char *s = str;
	if(nst<0){
		++nextst;
	}
//	printf("Phase %d -> Phase %d:\n", st, nst<0?nextst:nst);
	while(*str){
		if(*(str+1)){
			t2 = t + 1;
			if(t2 == 1){
				t2 = PHASE+1;
			}
			while(table[st][t2][(uint) *(str+1)]){
				++t2;
			}
		}else{
			final=1;
			if(nst<0){
				t2 = nextst;
			}else{
				t2 = nst;
			}
		}
		if(nextst > PHASE){
			fprintf(stderr, "Please increse PHASE.\n");
			exit(1);
		}
		if(table[st][t][(uint) *str]){
			if(table[st][t][(uint) *str] <= PHASE || final==1){
				fprintf(stderr, "Status collision.\n");
				exit(1);
			}else{
				t2=table[st][t][(uint) *str];
			}
		}
		table[st][t][(uint) *str] = t2;
//		printf("table[%2u][%2u][0x%02x] = %2u;\n", st, t, (uint) *str, t2);
		t = t2;
		++str;
	}
	return nextst;
}

void say(char str[]){
	write(ptt, str, strlen(str));
	atime=time(NULL);
}
