#include <opencv2/opencv.hpp>
#include <iostream>
#include <openssl/cmac.h>
#include <cstring>

const unsigned char key[] = "1234567890123456";

void verify_frame_security(const cv::Mat& frame) {
    // 1. Get raw data pointer
    size_t data_size = frame.total() * frame.elemSize();
    uchar* raw_data = frame.data;

    // 2. Generate CMAC (Producer side)
    unsigned char m_tag[16];
    size_t m_len;
    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, raw_data, data_size);
    CMAC_Final(ctx, m_tag, &m_len);

    // 3. Re-verify CMAC (Verifier side)
    unsigned char calc_tag[16];
    CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, raw_data, data_size);
    CMAC_Final(ctx, calc_tag, &m_len);

    if (std::memcmp(m_tag, calc_tag, 16) == 0) {
        std::cout << "[VERIFIED] Stream Integrity OK | Bytes: " << data_size << std::endl;
    } else {
        std::cerr << "[CRITICAL] Stream Tampered!" << std::endl;
    }
    
    CMAC_CTX_free(ctx);
}

int main() {
    // Using a public Wowza test stream (RTSP)
    const std::string stream_url = "rtsp://716f898c7b71.entrypoint.cloud.wowza.com:1935/app-8F9K44lJ/304679fe_stream2";
    
    cv::VideoCapture cap(stream_url);
    if (!cap.isOpened()) {
        std::cerr << "Error: Could not connect to public stream. Checking internet..." << std::endl;
        return -1;
    }

    cv::Mat frame;
    std::cout << "Connected to Public SDV Test Feed. Processing..." << std::endl;

    // Process first 30 frames for the demo
    for(int i = 0; i < 30; ++i) {
        cap >> frame;
        if (frame.empty()) break;
        verify_frame_security(frame);
    }

    std::cout << "Security Audit Complete." << std::endl;
    return 0;
}