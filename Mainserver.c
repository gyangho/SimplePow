#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <errno.h>

#define MAX_EVENTS	10

void errProc(const char*);

int main()
{
	int sock[3] = { 0 };
	int socknum = 0;
	struct sockaddr_in srvAddr;
	int readLen;
	char rBuff[BUFSIZ];
	char wBuff[BUFSIZ];

	char challenge[] = "201928042019285420201737"; //챌린지
	int difficulty = 8; //난이도
	unsigned int begin = 0; //nonce시작 값
	unsigned int end = 4294967295; //nonce최대 값

	int epfd, ready, readfd;
	struct epoll_event ev;
	struct epoll_event events[MAX_EVENTS];

	time_t start_time, end_time;
	double elapsed_time;

	printf("Main Server starting...\n");

	epfd = epoll_create(1); //epoll 객체 생성
	if (epfd == -1) errProc("epoll_create");

	printf("=========SETTING START==========\n");

	while (1)
	{
		printf("INPUT [NUMBER_OF_WORKINGSERVER]:");  //워킹서버 수 입력
		scanf("%d", &socknum);
		while (getchar() != '\n'); //입력버퍼 지우기
		if (socknum < 0 || socknum > 4) //워킹서버 수 제한
			printf("INVALID NUMBER OF SERVERS\n");
		else
			break;
	}
	for (int k = 0; k < socknum; k++)
	{
		char ip[30];
		int port;

		printf("==========WORKING_SERVER[%d]==========\n", k + 1); //워킹서버 정보 입력
		printf("INPUT [IP_ADDRESS] [PORT]:");
		scanf("%s %d", ip, &port);
		while (getchar() != '\n');

		sock[k] = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); //워킹서버 개수만큼 소켓 생성
		if (sock[k] == -1) errProc("socket");

		memset(&srvAddr, 0, sizeof(srvAddr));
		srvAddr.sin_addr.s_addr = inet_addr(ip);
		srvAddr.sin_family = AF_INET;
		srvAddr.sin_port = htons(port);

		if (connect(sock[k], (struct sockaddr*)&srvAddr, sizeof(srvAddr)) == -1)
		{
			close(sock[k]);
			errProc("Connect");
		}
		ev.events = EPOLLIN; //입력을 이벤트로 받는다
		ev.data.fd = sock[k];
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock[k], &ev) == -1) //epoll 객체 제어
			errProc("epoll_ctl");

		printf("=========CONNECTION COMPLETE==========\n\n");
	}
	printf("=========SETTING COMPLETE==========\n\n\n\n");

	printf("=========SENDING CHALLENGE&DIFFICULTY==========\n");
	unsigned int S_END = end;
	unsigned int S_BEGIN = begin;
	unsigned int S_range = (end - begin) / socknum; // working server 별로 계산할 nonce 범위

	for (int k = 0; k < socknum; k++) //[챌린지 난이도 시작값 끝값] 전송
	{
		begin = S_BEGIN + (S_range + 1) * k;
		end = begin + S_range;
		if (k == socknum - 1) // 마지막 지점이면 범위를 벗어나서 따로 처리함
			end = S_END;

		sprintf(wBuff, "%s %d %u %u", challenge, difficulty, begin, end); //워킹서버에게 정보 전송

		write(sock[k], wBuff, strlen(wBuff));
	}
	time(&start_time);

	printf("=========HASH COMPUTING STARTED==========\n");


	while (1) //서버 시작
	{
		int temp = 0;
		ready = epoll_wait(epfd, events, MAX_EVENTS, -1); //epoll 모니터링 시작
		if (ready == -1)
		{
			if (errno == EINTR) continue;
			else errProc("epoll_wait");
		}
		printf("%d\n", ready);
		for (int i = 0; i < ready; i++)
		{
			//IO
			readfd = events[i].data.fd;
			readLen = read(readfd, rBuff, sizeof(rBuff) - 1); //working서버가 전송하는 경우는 해쉬값 찾은 후 밖에없음
			rBuff[readLen] = '\0';
			time(&end_time);
			elapsed_time = difftime(end_time, start_time);  //시간 차이 계산
			printf("[WORKINGSERVER%d] %s\n", readfd - 2, rBuff); //해쉬 값과 nonce출력
			printf("Time Cost: %2.lf seconds\n", elapsed_time); //소모시간 출력
			temp = 1;
		}
		if (temp == 1)
			break;
	}
	for (int k = 0; k < socknum; k++)
	{
		strcpy(wBuff, "HASH_COMPUTING_HAS_DONE");		//연결종료를 알림
		write(sock[k], wBuff, strlen(wBuff));
		close(sock[k]);	//FIN패킷 전송
	}
	close(epfd);
	return 0;
}

void errProc(const char* str)
{
	fprintf(stderr, "%s: %s", str, strerror(errno));
	exit(1);
}