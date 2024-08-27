#include <stdint.h>
#include <stddef.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/libraw/libraw/libraw.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Instantiate FuzzedDataProvider with the input data
    FuzzedDataProvider stream(data, size);

    // Create an instance of LibRaw to call the member function on
    LibRaw libraw_instance;

    // Call the function we want to fuzz with the input data
    int result = libraw_instance.open_buffer(data, size);

    // Optionally, handle the result or perform additional operations
    if (result == LIBRAW_SUCCESS) {
        // Process the image if it was successfully opened
        libraw_instance.unpack();
        libraw_instance.dcraw_process();
        
        // The function selectCRXTrack does not exist, let's remove it
        // libraw_instance.selectCRXTrack();
    }

    return 0;
}