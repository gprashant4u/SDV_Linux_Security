#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <openssl/cmac.h>
#include <cstring>
#include <vector>

// Global resources for the "Virtual ECU"
std::mutex mtx;
std::condition_variable cv;
bool ready = false;

struct SharedBuffer {
    char data[1024];
    unsigned char tag[16];
} buffer;

const unsigned char key[] = "1234567890123456";

// --- Producer Thread (Camera Driver) ---
void camera_producer() {
    std::unique_lock<std::mutex> lock(mtx);
    
    const char* frame = "FRONT_CAM_FRAME_202";
    std::strcpy(buffer.data, frame);

    // Generate CMAC
    size_t len;
    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, frame, std::strlen(frame));
    CMAC_Final(ctx, buffer.tag, &len);
    CMAC_CTX_free(ctx);

    std::cout << "[Producer] Frame signed and ready." << std::endl;
    
    ready = true;
    lock.unlock();
    cv.notify_one(); // Signal the verifier
}

// --- Verifier Thread (Security ECU) ---
void security_verifier() {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, []{ return ready; }); // Wait for signal

    // Re-verify CMAC
    unsigned char calc_tag[16];
    size_t len;
    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, buffer.data, std::strlen(buffer.data));
    CMAC_Final(ctx, calc_tag, &len);
    CMAC_CTX_free(ctx);

    if (std::memcmp(buffer.tag, calc_tag, 16) == 0) {
        std::cout << "[Verifier] SUCCESS: Frame integrity verified in-thread!" << std::endl;
    } else {
        std::cerr << "[Verifier] FAILURE: Integrity check failed!" << std::endl;
    }
}

int main() {
    std::thread t1(camera_producer);
    std::thread t2(security_verifier);

    t1.join();
    t2.join();

    return 0;
}