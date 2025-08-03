#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/sha.h>

void errProc(const char* str);
void sighandler(int sig);
void sha256(const char* input, unsigned char* output);
int PoW(const char* challenge, int difficulty, unsigned int begin, unsigned int end, char* reval);

int process_count = 5;
int clntSd;

char* challenge;
int complexity; // 난이도

int main(int argc, char** argv)
{	
	// 시그널 핸들러 등록 (좀비프로세스 방지용)
	signal(SIGCHLD, sighandler);

	int srvSd;
	int PORT;
	struct sockaddr_in srvAddr, clntAddr;
	int clntAddrLen, readLen;
	char rBuff[BUFSIZ];
	char wBuff[BUFSIZ];
	pid_t pid[5];

	unsigned int begin;
	unsigned int end;

	/*===================서버설정 시작========================*/
	if (argc < 2)
	{
		printf("Usage: ./working [PORT]\n");
		errProc("PARAMETER ERROR");
	}

	PORT = atoi(argv[1]); //포트 지정
	srvSd = socket(AF_INET, SOCK_STREAM, 0);//소켓 생성

	if (srvSd == -1)
	{
		errProc("SOCKET");
	}
	//소켓 설정
	memset(&srvAddr, 0, sizeof(srvAddr));
	srvAddr.sin_family = AF_INET;
	srvAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	srvAddr.sin_port = htons(PORT);
	//소켓 바인드
	if (bind(srvSd, (struct sockaddr*)&srvAddr, sizeof(srvAddr)) == -1)
	{
		errProc("BIND");
	}
	//소켓 listen
	if (listen(srvSd, 1) == -1)
	{
		errProc("LISTEN");
	}

	/*===================서버설정 종료========================*/

	clntAddrLen = sizeof(clntAddr);
	//메인서버 접속 accept
	clntSd = accept(srvSd, (struct sockaddr*)&clntAddr, &clntAddrLen);

	if (clntSd == -1)
	{
		printf("Accept Error");
		errProc("ACCEPT");
	}

	/*=============메인서버로부터 값 입력받기=================*/

	readLen = read(clntSd, rBuff, sizeof(rBuff) - 1);
	if (readLen == -1)
	{
		printf("Read Error");
		errProc("READ");
	}
	rBuff[readLen] = '\0';

	printf("==========INPUT FROM MAINSERVER==========\n");
	challenge = strtok(rBuff, " ");
	printf("CHALLENGE: %s\n", challenge);
	complexity = atoi(strtok(NULL, " "));
	printf("COMPLEXITY: %d\n", complexity);
	begin = strtoul(strtok(NULL," "),NULL,10);
	printf("BEGIN: %u\n", begin);
	end = strtoul(strtok(NULL, " "),NULL,10);
	printf("END: %u\n", end);
	printf("==========INPUT PROCESS ENDED============\n\n\n\n");


	while (1) //혹시 모를 유효하지 않은 값 처리.
	{
		char* ptr;
		ptr = strtok(NULL, " ");
		if (ptr == NULL)
			break;
		printf("%s\n", ptr);
	}

	/*===============메인서버로부터 값 입력완료=================*/
	unsigned int process_END = end;                       // process의 end 저장...
	unsigned int process_BEGIN= begin;
	unsigned int p_range = (end - begin) / process_count; // process별로 계산할 nonce 범위

	for (int p = 0; p < process_count; p++) // process_count만큼 자식 프로세스 만듦
	{
		begin = process_BEGIN + (p_range + 1) * p;
		end = begin + p_range;
		if (p==process_count-1) // 마지막 지점이면 범위를 벗어나서 따로 처리함
			end = process_END;

		printf("FORK[%d]\n", p + 1);

		pid[p] = fork();

		if (pid[p] < 0)
			errProc("fork");

	/*===============자식 프로세스=================*/
		else if (pid[p] == 0)
		{
			int r=PoW(challenge, complexity, begin, end, wBuff);
			if (r==1)
			{;
				//nonce 및 해쉬 값 메인서버로 전송
				write(clntSd, wBuff, strlen(wBuff));
			}
			printf("========CHILD PROCESS[%d] HAS FINISHED========\n", p);
			exit(0);
		}
	}
	/*==================부모 프로세스==================*/
		while (1)
		{
			//메인서버로부터 입력받기
			readLen = read(clntSd, rBuff, sizeof(rBuff) - 1);
			rBuff[readLen] = '\0';
			//main서버에서 close하면 자식프로세스 종료
			//->signalhandler통해 wait()처리 후, 소켓 닫고 자식프로세스들 종료
			if (readLen == 0)
			{				
				printf("EXITTING......\n");
				close(clntSd);
				for(int i; i<process_count; i++)
					kill(pid[i],SIGINT);        //자식프로세스에게 종료시그널 전송
				break;
			}
			//close한 게 아니라면 온거 그대로 출력
			printf("[MAIN SERVER] %s\n", rBuff);
		}
		return 0;
}

void sighandler(int sig) //SIGCHLD감지하여 좀비프로세스 방지
{
	wait();//좀비프로세스 방지를 위한 wait()
}

void errProc(const char* str)
{
	fprintf(stderr, "%s %s \n", str, strerror(errno));
	exit(1);
}

// SHA256 해시 값 생성
void sha256(const char* input, unsigned char* output) {
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, input, strlen(input));
	SHA256_Final(output, &sha256);
}

// 난이도에 해당하는 해시 값 find
int PoW(const char* challenge, int difficulty, unsigned int begin, unsigned int end, char* reval) 
{
	printf("BEGIN: %u\n",begin);
	printf("END: %u\n",end);
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned int nonce = begin;
	char temp[30];
	int valid;

	strcpy(reval, "HASH_VALUE: ");

	// 챌린지 값과 nonce를 조합하여 해시 값 계산 후 난이도에 맞는지 확인
	do {
		char input[64];
		sprintf(input, "%s%08x", challenge, nonce);
		sha256(input, hash);
		valid = 1;
		// 난이도 체크
		for (int i = 0; i < difficulty; i++) 
        {
            if (hash[i/2] >> (4 * (1 - i % 2)) & 0x0F) 
            {
                valid = 0;
                break;
            }
        }
		if (valid==1) //해쉬 값을 찾았을 경우
		{
			printf("VALID!\n");
			for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
			{
				sprintf(temp, "%02x", hash[i]);
				strcat(reval, temp);
			}
			sprintf(temp, "\nNONCE_VALUE: %08x", nonce);
			strcat(reval, temp);
			break;
		}
		nonce++; // nonce 값을 증가
	} while (nonce <= end);
	return valid;
}
