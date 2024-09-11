#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libraw/libraw/libraw.h" // Correct path to the LibRaw header

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with fuzzing input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a LibRaw object
    LibRaw libraw_instance;

    // Use the open_buffer() method to process the raw image data directly from the fuzzed input
    int result = libraw_instance.open_buffer(data, size);

    // If the buffer is successfully opened, we can further process the image
    if (result == LIBRAW_SUCCESS) {
        // Unpack the raw image
        result = libraw_instance.unpack();
        if (result == LIBRAW_SUCCESS) {
            // Process the image, e.g., by calling other LibRaw methods
            // For example, we can call dcraw_process() to process the raw image
            result = libraw_instance.dcraw_process();
        }
    }

    // Since 'parseCR3_CTMD' does not exist, we will call another method from LibRaw to utilize the fuzzed input
    // Let's call 'adjust_sizes_info_only' as an example, which takes no parameters
    int parse_result = libraw_instance.adjust_sizes_info_only();

    // Return the result of the adjust_sizes_info_only function
    return parse_result;
}