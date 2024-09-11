#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libraw/libraw/libraw.h" // Correct path for the LibRaw header file
#include <vector>

class LibRawFuzzer : public LibRaw {
public:
    using LibRaw::crxLoadDecodeLoop;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a portion of the input data to use as the first parameter (void*)
    std::vector<uint8_t> buffer = fuzzed_data.ConsumeBytes<uint8_t>(fuzzed_data.remaining_bytes() / 2);
    void *ptr = buffer.data();

    // Consume an integer value for the second parameter
    int int_param = fuzzed_data.ConsumeIntegral<int>();

    // Create an instance of the subclass and call the function-under-test
    LibRawFuzzer libraw_fuzzer;
    libraw_fuzzer.crxLoadDecodeLoop(ptr, int_param);

    return 0;
}