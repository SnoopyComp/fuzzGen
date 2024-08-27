#include <fuzzer/FuzzedDataProvider.h>
#include <libraw/libraw.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Create an instance of LibRaw
    LibRaw rawProcessor;

    // Use the input data to simulate a RAW file
    std::vector<uint8_t> raw_data(data, data + size);

    // Open the RAW data from memory
    int open_result = rawProcessor.open_buffer(raw_data.data(), raw_data.size());
    if (open_result != LIBRAW_SUCCESS) {
        return 0; // Return if the RAW data is not valid
    }

    // Unpack the RAW data
    int unpack_result = rawProcessor.unpack();
    if (unpack_result != LIBRAW_SUCCESS) {
        return 0; // Return if unpacking fails
    }

    // Process the image (this function does some processing based on the unpacked data)
    int process_result = rawProcessor.dcraw_process();
    if (process_result != LIBRAW_SUCCESS) {
        return 0; // Return if processing fails
    }

    // Call the sraw_midpoint function as required
    int midpoint_result = rawProcessor.sraw_midpoint();

    // Return the result
    return midpoint_result;
}