#include <cstdint>
#include <cstdlib>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a string for the file name
    std::string filename = fuzzed_data.ConsumeRandomLengthString(100);

    // Consume a string for the mode
    std::string mode = fuzzed_data.ConsumeRandomLengthString(10);

    // Ensure the mode string is not empty and has a valid mode character
    if (mode.empty() || (mode.find_first_of("rwa+") == std::string::npos)) {
        return 0;
    }

    // Call the function-under-test
    TIFF *tiff = TIFFOpen(filename.c_str(), mode.c_str());

    // If TIFFOpen succeeded, close the TIFF file
    if (tiff != nullptr) {
        TIFFClose(tiff);
    }

    return 0;
}