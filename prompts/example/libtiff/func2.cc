#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <tiffio.h>
#include <unistd.h>
#include <vector>
#include <string.h> // For memset

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider stream(data, size);

    // Create a temporary file to simulate file descriptor operations
    char temp_filename[] = "/tmp/fuzz_tiff_XXXXXX";
    int fd = mkstemp(temp_filename);
    if (fd == -1) {
        return 0;
    }

    // Write fuzz data to the temporary file
    std::vector<uint8_t> file_data = stream.ConsumeBytes<uint8_t>(size);
    if (write(fd, file_data.data(), file_data.size()) == -1) {
        close(fd);
        return 0;
    }

    // Reset file descriptor to the beginning of the file
    lseek(fd, 0, SEEK_SET);

    // Generate other parameters for TIFFFdOpenExt
    std::string mode = stream.ConsumeRandomLengthString(10);
    std::string name = stream.ConsumeRandomLengthString(10);

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

    // Create TIFFOpenOptions object
    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    if (!options) {
        close(fd);
        unlink(temp_filename);
        return 0;
    }

    // Call the function-under-test
    TIFF *tiff = TIFFFdOpenExt(fd, name.c_str(), mode.c_str(), options);

    // Perform any necessary cleanup
    if (tiff) {
        TIFFClose(tiff);
    }

    TIFFOpenOptionsFree(options);
    