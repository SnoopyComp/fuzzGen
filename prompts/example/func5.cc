#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libraw/libraw/libraw.h"
#include <vector>

// Derived class to expose the protected crxLoadDecodeLoop method
class LibRawFuzzer : public LibRaw {
public:
    using LibRaw::crxLoadDecodeLoop;
};

// Fuzzing entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with fuzzing data
    FuzzedDataProvider fuzzedDataProvider(data, size);

    // Ensure there is enough data to proceed
    if (size < sizeof(int)) {
        return 0;
    }

    // Consume a vector of bytes to use as the void* parameter
    std::vector<uint8_t> buffer = fuzzedDataProvider.ConsumeBytes<uint8_t>(fuzzedDataProvider.remaining_bytes());
    void* buffer_ptr = buffer.data();

    // Consume an integer value for the second parameter
    int int_param = fuzzedDataProvider.ConsumeIntegral<int>();

    // Ensure the buffer is not empty and the integer parameter is within a valid range
    if (!buffer.empty() && int_param > 0) {
        // Call the function-under-test
        LibRawFuzzer libRawInstance;
        libRawInstance.crxLoadDecodeLoop(buffer_ptr, int_param);
    }

    return 0;
}