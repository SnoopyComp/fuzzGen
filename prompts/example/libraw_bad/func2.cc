#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libraw/libraw/libraw.h" // Correct path to the LibRaw header file

// Fuzzing harness for LibRaw::sraw_midpoint
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the given data and size
    FuzzedDataProvider fuzzed_data(data, size);

    // Create an instance of LibRaw
    LibRaw libraw_instance;

    // Set up the necessary fields in libraw_instance to ensure sraw_midpoint() is meaningfully invoked
    // For example, we can set up the rawdata.sizes structure
    libraw_instance.imgdata.sizes.raw_width = fuzzed_data.ConsumeIntegral<uint16_t>();
    libraw_instance.imgdata.sizes.raw_height = fuzzed_data.ConsumeIntegral<uint16_t>();

    // Ensure the rawdata.raw_image is allocated and populated with some data
    int raw_image_size = libraw_instance.imgdata.sizes.raw_width * libraw_instance.imgdata.sizes.raw_height;
    if (raw_image_size > 0 && raw_image_size < size) {
        libraw_instance.imgdata.rawdata.raw_image = new ushort[raw_image_size];
        for (int i = 0; i < raw_image_size; ++i) {
            libraw_instance.imgdata.rawdata.raw_image[i] = fuzzed_data.ConsumeIntegral<ushort>();
        }
    } else {
        // If the size is invalid, clean up and return
        return 0;
    }

    // Call the function-under-test
    int result = libraw_instance.sraw_midpoint();

    // Clean up allocated memory
    delete[] libraw_instance.imgdata.rawdata.raw_image;

    // Return 0 to indicate successful execution
    return 0;
}