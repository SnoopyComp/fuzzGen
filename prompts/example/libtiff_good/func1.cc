#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>  // For write, close, lseek, and unlink

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a temporary file to simulate file descriptor input
    char temp_filename[] = "/tmp/fuzz_tiff_XXXXXX";
    int fd = mkstemp(temp_filename);
    if (fd == -1) {
        return 0;
    }

    // Write fuzz data to the temporary file
    std::vector<uint8_t> file_data = fuzzed_data.ConsumeBytes<uint8_t>(size);
    if (write(fd, file_data.data(), file_data.size()) == -1) {
        close(fd);
        return 0;
    }

    // Reset file descriptor to the beginning of the file
    lseek(fd, 0, SEEK_SET);

    // Generate other parameters for TIFFFdOpen
    std::string mode = fuzzed_data.ConsumeRandomLengthString(10);
    std::string name = fuzzed_data.ConsumeRandomLengthString(10);

    // Ensure mode is a valid TIFF mode
    if (mode.empty()) {
        mode = "r"; // Default to read mode
    } else {
        mode[0] = mode[0] % 2 == 0 ? 'r' : 'w'; // Simplify to 'r' or 'w'
    }

    // Ensure name is not empty
    if (name.empty()) {
        name = "fuzz_tiff"; // Default name
    }

    // Call the function-under-test
    TIFF *tiff = TIFFFdOpen(fd, name.c_str(), mode.c_str());

    // Perform any necessary cleanup
    if (tiff) {
        TIFFClose(tiff);
    }

    close(fd);
    unlink(temp_filename);

    return 0;
}
