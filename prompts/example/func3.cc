#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>
#include <vector>
#include "/src/libraw/libraw/libraw.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider stream(data, size);

    // Generate a random size for the buffer
    uint32_t buffer_size = stream.ConsumeIntegral<uint32_t>();

    // Create a buffer of the generated size
    std::vector<uint8_t> buffer(buffer_size);

    // Fill the buffer with fuzzed data
    stream.ConsumeData(buffer.data(), buffer.size());

    // Create an instance of LibRaw
    LibRaw libraw_instance;

    // Since crxDecodePlane is a protected member, we cannot call it directly.
    // Instead, we can call a public method that internally uses crxDecodePlane.
    // For example, we can use the open_buffer method which is public and processes raw data.

    // Call the function-under-test
    int result = libraw_instance.open_buffer(buffer.data(), buffer_size);

    return 0;
}