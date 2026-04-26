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

    int fd = shm_open(shm_name, O_RDONLY, 0666);
    char* ptr = (char*)mmap(0, SIZE, PROT_READ, MAP_SHARED, fd, 0);

    char frame_data[256];
    std::strcpy(frame_data, ptr);
    unsigned char stored_tag[16];
    std::memcpy(stored_tag, ptr + 1024, 16);

    unsigned char calc_tag[16];
    size_t calc_len;
    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, frame_data, std::strlen(frame_data));
    CMAC_Final(ctx, calc_tag, &calc_len);

    if (std::memcmp(stored_tag, calc_tag, 16) == 0) {
        std::cout << "[Verifier] SUCCESS: Frame integrity verified. Content: " << frame_data << std::endl;
    } else {
        std::cerr << "[Verifier] CRITICAL: Frame tampered!" << std::endl;
    }

    CMAC_CTX_free(ctx);
    munmap(ptr, SIZE);
    close(fd);
    return 0;
}
