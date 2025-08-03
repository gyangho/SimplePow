#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <string.h>
#include <time.h>

// SHA256 해시 값 생성
void sha256(const unsigned char* input, unsigned char* output) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, strlen(input));
    SHA256_Final(output, &sha256);
}

// 난이도에 해당하는 해시 값 find
void PoW(const unsigned char* challenge, int difficulty) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int nonce = 0;
    char temp[3];
    char reval[BUFSIZ] = { };
    int help = 0;
    int d = 0;

    printf("CHALLENGE: %s\n", challenge);
    printf("DIFFICULTY: %d\n", difficulty);

    // 챌린지 값과 nonce를 조합하여 해시 값 계산 후 난이도에 맞는지 확인
    do {
        if (nonce % 100000000 == 0)
        {
            printf("%d\n", d);
            d++;
        }
        if (nonce == 4294967295)
        {
            printf("no dap\n");
            break;
        }
        char input[64];
        sprintf(input, "%s%08x", challenge, nonce);
        sha256(input, hash);

        // 난이도 체크
        int valid = 1;
        for (int i = 0; i < difficulty; i++)
        {
            if (hash[i / 2] >> (4 * (1 - i % 2)) & 0x0F)
            {
                valid = 0;
                break;
            }
        }
        if (valid) {  //해쉬 값을 찾았을 경우
            {
                printf("해시 값을 찾았습니다!\n");
                printf("챌린지 값: %s\n", challenge);
                printf("Nonce: %08x\n", nonce);
                printf("해시 값: ");
                for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
                {
                    printf("%02x", hash[i]);
                }
                printf("\n");
                break;
            }
        }
        nonce++; // nonce 값을 증가
    } while (1);
}

int main() {
    const char* challenge = "201928042019285420201737";
    int difficulty = 8; // 7,8로 조정
    time_t start_time, end_time;
    double elapsed_time;

    time(&start_time);
    PoW(challenge, difficulty);
    time(&end_time);
    elapsed_time = difftime(end_time, start_time);
    printf("Time Cost: %2.lf seconds\n", elapsed_time);

    return 0;
}
