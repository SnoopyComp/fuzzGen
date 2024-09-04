#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider stream(data, size);

  // Create a temporary file to simulate file descriptor input
  FILE* temp_file = tmpfile();
  if (!temp_file) {
    return 0;
  }

  // Write fuzz data to the temporary file
  fwrite(data, 1, size, temp_file);
  fflush(temp_file);
  fseek(temp_file, 0, SEEK_SET);

  // Get the file descriptor
  int fd = fileno(temp_file);

  // Consume strings for mode and name
  std::string name = stream.ConsumeRandomLengthString(20);
  std::string mode = stream.ConsumeRandomLengthString(5);

  // Ensure mode is not empty and has valid characters for file mode
  if (mode.empty() || mode.find_first_not_of("rwb+") != std::string::npos) {
    mode = "r";  // Default to read mode
  }

  // Call the function-under-test
  TIFF* tiff = TIFFFdOpen(fd, name.c_str(), mode.c_str());

  // Clean up
  if (tiff) {
    TIFFClose(tiff);
  }
  fclose(temp_file);

  return 0;
}