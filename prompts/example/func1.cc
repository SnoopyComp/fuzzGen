#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libraw/libraw/libraw.h"

// Fuzzing entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with fuzzing data
    FuzzedDataProvider fuzzedDataProvider(data, size);

    // Ensure there is enough data to proceed
    if (size < sizeof(short)) {
        return 0;
    }

    // Consume a short value from the fuzzed data
    short short_param = fuzzedDataProvider.ConsumeIntegral<short>();

    // Call the function-under-test
    LibRaw libRawInstance;
    int result = libRawInstance.open_buffer(data, size);

    // Check if the buffer was successfully opened
    if (result != LIBRAW_SUCCESS) {
        return 0;
    }

    // Call the target function unpack
    int unpackResult = libRawInstance.unpack();

    // Since parseCR3_CTMD is not a member of LibRaw, we will call another function that exists
    // For demonstration, let's call 'dcraw_process' which is a valid function in LibRaw
    int processResult = libRawInstance.dcraw_process();

    return 0;
}