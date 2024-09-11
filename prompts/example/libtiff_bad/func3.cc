#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>
#include <cstdio>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a string for the file name
    std::string filename = "/tmp/test.tiff"; // Use a fixed filename for simplicity

    // Consume a string for the mode
    std::string mode = fuzzed_data.ConsumeRandomLengthString(10);

    // Ensure mode is not empty and has valid characters for file mode
    if (mode.empty() || mode.find_first_not_of("rwa+") != std::string::npos) {
        mode = "r";  // Default to read mode
    }

    // Create a temporary file to simulate file operations
    FILE* temp_file = fopen(filename.c_str(), "wb+");
    if (!temp_file) {
        return 0;
    }

    // Write fuzz data to the temporary file
    fwrite(data, 1, size, temp_file);
    fflush(temp_file);
    fseek(temp_file, 0, SEEK_SET);

    // Close the file to ensure TIFFOpen can open it properly
    fclose(temp_file);

    // Call the function-under-test
    TIFF* tiff = TIFFOpen(filename.c_str(), mode.c_str());

    // Perform any necessary cleanup
    if (tiff) {
        TIFFClose(tiff);
    }

    // Remove the temporary file
    remove(filename.c_str());

    return 0;
}
