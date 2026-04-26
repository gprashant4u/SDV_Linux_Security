#include <iostream>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/cmac.h>
#include <cstring>

int main() {
    const char* shm_name = "/sdv_secure_stream";
    const int SIZE = 4096;
    const unsigned char key[] = "1234567890123456"; 

    int fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
    ftruncate(fd, SIZE);
    char* ptr = (char*)mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    const char* frame_content = "CAM_FRAME_ID_101_STATUS_OK";
    std::strcpy(ptr, frame_content);

    unsigned char m_tag[16];
    size_t m_len;
    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, frame_content, std::strlen(frame_content));
    CMAC_Final(ctx, m_tag, &m_len);

    std::memcpy(ptr + 1024, m_tag, 16);
    std::cout << "[Producer] Frame written and signed with CMAC." << std::endl;

    CMAC_CTX_free(ctx);
    munmap(ptr, SIZE);
    close(fd);
    return 0;
}
