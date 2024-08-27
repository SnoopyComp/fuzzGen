#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libraw/libraw/libraw.h"
#include <vector>
#include <cstring> // For memset

// Derived class to expose the protected crxDecodePlane method
class LibRawFuzzer : public LibRaw {
public:
    using LibRaw::crxDecodePlane;
};

// Fuzzing entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with fuzzing data
    FuzzedDataProvider fuzzedDataProvider(data, size);

    // Ensure there is enough data to proceed
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Consume a vector of bytes to use as the void* parameter
    std::vector<uint8_t> buffer = fuzzedDataProvider.ConsumeBytes<uint8_t>(fuzzedDataProvider.remaining_bytes());
    void* buffer_ptr = buffer.data();

    // Consume a uint32_t value for the second parameter
    uint32_t uint32_param = fuzzedDataProvider.ConsumeIntegral<uint32_t>();

    // Ensure the buffer is not empty and properly allocated
    if (!buffer.empty() && uint32_param > 0) {
        // Allocate a buffer for the crxDecodePlane function
        std::vector<uint8_t> decodeBuffer(uint32_param);
        void* decodeBuffer_ptr = decodeBuffer.data();

        // Initialize the decode buffer to avoid uninitialized memory issues
        std::memset(decodeBuffer_ptr, 0, uint32_param);

        // Call the function-under-test
        LibRawFuzzer libRawInstance;
        try {
            libRawInstance.crxDecodePlane(decodeBuffer_ptr, uint32_param);
        } catch (...) {
            // Catch any exceptions to prevent the fuzzer from crashing
        }
    }

    return 0;
}