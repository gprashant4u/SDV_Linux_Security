#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <openssl/cmac.h>
#include <cstring>
#include <string>

// Architecture: Each camera gets its own "Stream" object
struct CameraStream {
    int id;
    char data[1024];
    unsigned char tag[16];
    std::mutex mtx; // Individual lock per camera for better concurrency
};

const unsigned char key[] = "1234567890123456";

// Task: Simulate a specific camera stream
void process_camera(CameraStream* stream) {
    // 1. Producer Logic (Signing)
    {
        std::lock_guard<std::mutex> lock(stream->mtx);
        std::string frame = "CAMERA_" + std::to_string(stream->id) + "_DATA_FLOWING";
        std::strcpy(stream->data, frame.c_str());

        size_t len;
        CMAC_CTX *ctx = CMAC_CTX_new();
        CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL);
        CMAC_Update(ctx, stream->data, std::strlen(stream->data));
        CMAC_Final(ctx, stream->tag, &len);
        CMAC_CTX_free(ctx);
        
        std::cout << "[Cam " << stream->id << "] Data signed." << std::endl;
    }

    // 2. Verifier Logic (In a real ECU, this might be a separate thread, 
    // but here we simulate the verification of that specific stream)
    {
        std::lock_guard<std::mutex> lock(stream->mtx);
        unsigned char calc_tag[16];
        size_t len;
        CMAC_CTX *ctx = CMAC_CTX_new();
        CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL);
        CMAC_Update(ctx, stream->data, std::strlen(stream->data));
        CMAC_Final(ctx, calc_tag, &len);
        CMAC_CTX_free(ctx);

        if (std::memcmp(stream->tag, calc_tag, 16) == 0) {
            std::cout << "[Cam " << stream->id << "] SUCCESS: Integrity Verified." << std::endl;
        } else {
            std::cerr << "[Cam " << stream->id << "] FAILURE: Tamper Detected!" << std::endl;
        }
    }
}

int main() {
    const int NUM_CAMERAS = 4; // Scalable to 8, 12, etc.
    std::vector<std::thread> workers;
    std::vector<CameraStream> streams(NUM_CAMERAS);

    // Initialize IDs
    for(int i = 0; i < NUM_CAMERAS; ++i) streams[i].id = i + 1;

    std::cout << "Starting SDV Sensor Suite (Scalable Vector Model)..." << std::endl;

    // Launch all camera threads
    for (int i = 0; i < NUM_CAMERAS; ++i) {
        workers.push_back(std::thread(process_camera, &streams[i]));
    }

    // Join all threads back to main
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    std::cout << "All camera streams processed securely." << std::endl;
    return 0;
}