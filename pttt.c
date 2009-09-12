#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define PHASE 24
uint table[PHASE+1][256][256]={0};
#include "common.c"

int sshd;

int main(int ac, char *av[]){
	struct sockaddr_in ptt_addr, sshd_addr;
	uchar ptt_buf[BUFSIZE], ssh_buf[BUFSIZE], tmp[16];
	uchar b64_buf[BUFSIZE*2]={0};
	b64 base64;
	ssize_t i, ptt_len, ssh_len;
	uint phase=0, status=0;
	uchar *cpt, *wpt;
	int wptfreeze=0, line=0, hflag=0;

	for (i = 0; i < 256; ++i) {
		b64_btable[i]=0xff;
	}
	for (i = 0; i < 64; ++i){
		b64_btable[b64_ftable[i]]=i;
	}
//	b64_btable['='] = 0;	//Comment for speed

	uint p_username = buildtable(0, "\xb5\xf9\xa5\x55:", -1);
	uint p_password = buildtable(p_username, "\xb1\x4b\xbd\x58\x3a", -1);
	uint p_loginfail = buildtable(p_password, "\xab\x5f\xa5\xce\xa4\x48\xae\x61\xaa\xba\xa6\x57\xa6\x72\xb0\xda\xa1\x48", -1);
	uint p_clearfail = buildtable(p_password, "\xb9\xc1\xb8\xd5\xaa\xba\xb0\x4f\xbf\xfd\xb6\xdc\x28\x59\x2f\x4e\x29\x3f\x5b\x4e\x5d", -1);
	uint p_kicklogin = buildtable(p_password, "\x6c\x6f\x67\x69\x6e\x20\xb6\xdc\xa1\x48\x5b\x59\x2f\x6e\x5d", -1);
	uint p_anykey = buildtable(p_password, "\xa5\xf4\xb7\x4e\xc1\xe4", -1);
	uint p_mainmenu = buildtable(p_password, "\xb2\xe1\xa4\xd1\xb0\xcf", -1);
	uint p_talkmenu = buildtable(p_mainmenu, "\xa7\xe4\xa4\x48\xb2\xe1\xb2\xe1", -1);
	uint p_talkto = buildtable(p_talkmenu, "\xa5\x4e\xb8\xb9:", -1);
	uint p_talkopt = buildtable(p_talkto, "\xbf\xf9\xa4\x48\xa4\x46\x3f\x5b\x4e\x5d", -1);
	uint p_talking = buildtable(p_talkopt, "\xbd\xcd\xa4\xd1\xbb\xa1\xa6\x61", -1);
	uint p_pk_start = buildtable(p_talking, "<", -1);
	uint p_pk_end = buildtable(p_pk_start, ">", -1);
	uint p_control = buildtable(p_pk_start, "\x1b", -1);
	uint p_control_end=
		buildtable(p_control, "\x37", -1);
		buildtable(p_control, "\x38", p_control_end);
		buildtable(p_control, "\x44", p_control_end);
	uint p_control_block=
		buildtable(p_control, "\x5b", -1);
	uint p_control_block_number=
		buildtable(p_control_block, "0", -1);
		buildtable(p_control_block, "1", p_control_block_number);
		buildtable(p_control_block, "2", p_control_block_number);
		buildtable(p_control_block, "3", p_control_block_number);
		buildtable(p_control_block, "4", p_control_block_number);
		buildtable(p_control_block, "5", p_control_block_number);
		buildtable(p_control_block, "6", p_control_block_number);
		buildtable(p_control_block, "7", p_control_block_number);
		buildtable(p_control_block, "8", p_control_block_number);
		buildtable(p_control_block, "9", p_control_block_number);
	uint p_control_block_end=
		buildtable(p_control_block, "r", -1);
		buildtable(p_control_block, "K", p_control_block_end);
	uint p_control_block_h=
		buildtable(p_control_block, "H", -1);
	uint p_ignore_section=
		buildtable(p_control_block, "m", -1);
	uint p_ignore_section_end=
		buildtable(p_ignore_section, "\x1b\x5b\x30m", -1);
		buildtable(p_ignore_section, ":", p_ignore_section_end);

	if(ac != 3){
		fprintf(stderr, "Usage: %s ListenIP ListenPort", av[0]);
		exit(1);
	}

	ptt = socket(PF_INET, SOCK_STREAM, 0);
	ptt_addr.sin_family = PF_INET;
	ptt_addr.sin_addr.s_addr = inet_addr("140.112.172.11");
	ptt_addr.sin_port = htons(23);

	if(connect(ptt, (struct sockaddr *) &ptt_addr, sizeof(ptt_addr)) == -1){
		perror(av[0]);
		exit(1);
	}

	fcntl(ptt, F_SETFL, O_NONBLOCK | fcntl(ptt, F_GETFL, 0));

	putchar('\n');
	atime=time(NULL);

	while(1){
		i=time(NULL);
		if(i-atime>30){
			atime=i;
			write(ptt, "\0", 1);
			printf("Keeps connection.\n");
		}
		usleep(200);
		if(phase == p_talkopt){
			say("\r\n");
		}
		if((ptt_len = read(ptt, ptt_buf, sizeof(ptt_buf)))>0){
			for(i=0 ; i<ptt_len ; ++i){
				if(phase == p_pk_start){
					*wpt=ptt_buf[i];
				}
				status = table[phase][status][(uint) ptt_buf[i]];
				if(phase == p_talking && status == p_pk_start){
					status = 0;
//					printf("Begin of packet.\n");
					wpt = b64_buf;
					phase = p_pk_start;
					wptfreeze=2;
				}else if(phase == p_pk_start && status == p_pk_end){
					status = 0;
//					printf("End of packet.\n");
					*wpt=0;
					phase = p_talking;
					if(*b64_buf){
						base64=b64_decode(b64_buf);
						write(ssh, base64.dat, base64.len);
						free(base64.dat);
					}
				}else if(phase == p_pk_start && status == p_control){
					status = 0;
					phase = p_control;
					wptfreeze=1;
				}else if(phase == p_control){
					if(status == p_control_end){
						status = 0;
						phase = p_pk_start;
						wptfreeze=2;
					}else if(status == p_control_block){
						status = 0;
						phase = p_control_block;
						line=0;
						hflag=0;
					}
				}else if(phase == p_control_block){
					if(status == p_control_block_end){
						status = 0;
						phase = p_pk_start;
						wptfreeze=2;
					}else if(status == p_ignore_section){
						status = 0;
						phase = p_ignore_section;
					}else if(status == p_control_block_h){
						status = 0;
						phase = p_pk_start;
						if(line>12){
							wptfreeze=2;
						}else{
							wptfreeze=1;
						}
					}else if(status == p_control_block_number){
						status = 0;
						if(hflag==0){
							line*=10;
							line+=ptt_buf[i]-'0';
						}
					}else{
						hflag=1;
					}
				}else if(phase==p_ignore_section && status==p_ignore_section_end){
					status = 0;
					phase = p_pk_start;
					wptfreeze=2;
				}else if(phase == 0 && status == p_username){
					status = 0;
					phase = p_username;
					printf("Username:");
					fflush(stdin);
					fgets(tmp, sizeof(tmp), stdin);
					say(trim(tmp));
					say("\r\n");
				}else if(phase == p_username && status == p_password){
					status = 0;
					phase = p_password;
					printf("Password:");
					fflush(stdin);
					echooff();
					fgets(tmp, sizeof(tmp), stdin);
					echoon();
					putchar('\n');
					say(trim(tmp));
					say("\r\n");
				}else if(phase == p_password){
					if(status == p_clearfail){
						status = 0;
						say("n\r\n");
					}else if(status == p_loginfail){
						status = 0;
						fprintf(stderr, "Failed login.\n");
						exit(1);
					}else if(status == p_kicklogin){
						status = 0;
						printf("Kick other login.\n");
						say("y\r\n");
					}else if(status == p_anykey){
						status = 0;
						printf("Continue.\n");
						say("\r\n");
					}else if(status == p_mainmenu){
						status = 0;
						phase = p_mainmenu;
						printf("At main menu.\n");
						say("t\r\n");
					}
				}else if(phase == p_mainmenu && status == p_talkmenu){
					status = 0;
					phase = p_talkmenu;
					printf("At talk menu.\n");
					say("t\r\n");
				}else if(phase == p_talkmenu && status == p_talkto){
					status = 0;
					phase = p_talkto;
					printf("Talk to:");
					fflush(stdin);
					fgets(tmp, sizeof(tmp), stdin);
					say(trim(tmp));
					say("\r\n");
				}else if(phase == p_talkto && status == p_talkopt){
					status = 0;
					phase = p_talkopt;
					printf("Talk option.\n");
					say("t\r\n");
				}else if(phase == p_talkopt && status == p_talking){
					status = 0;
					phase = p_talking;
					printf("Talking now.\n");
					sshd = socket(PF_INET, SOCK_STREAM, 0);
					sshd_addr.sin_family = PF_INET;
					sshd_addr.sin_addr.s_addr = inet_addr(av[1]);
					sshd_addr.sin_port = htons(atoi(av[2]));
					if(bind(sshd, (struct sockaddr *) &sshd_addr, sizeof(sshd_addr)) == -1){
						perror(av[0]);
						exit(1);
					}
					if(listen(sshd, 5) == -1){
						perror(av[0]);
						exit(1);
					}
					if((ssh=accept(sshd, NULL, NULL)) == -1){
						perror(av[0]);
						exit(1);
					}
					fcntl(ssh, F_SETFL, O_NONBLOCK | fcntl(ssh, F_GETFL, 0));
					printf("Connection established.\n");
					say("{}\r\n");
					online=1;
				}
				if((phase==p_pk_start) && (b64_btable[*wpt]!=0xff) && (wptfreeze==0)){
					++wpt;
				}
				if(wptfreeze==2){
					wptfreeze=0;
				}
			}
		}
		if((online == 1) && ((ssh_len = read(ssh, ssh_buf, sizeof(ssh_buf)))>0)){
			say("{");
			say(cpt=b64_encode(ssh_buf, ssh_len));
			free(cpt);
			say("}\r\n");
		}
	}

	return 0;
}
