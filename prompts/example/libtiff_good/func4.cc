#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);

  // Generate a filename and mode string
  std::string filename = fuzzed_data.ConsumeRandomLengthString(100);
  std::string mode = fuzzed_data.ConsumeRandomLengthString(10);

  // Ensure filename and mode are not empty
  if (filename.empty() || mode.empty()) {
    return 0;
  }

  // Create default TIFFOpenOptions
  TIFFOpenOptions* options = TIFFOpenOptionsAlloc();

  // Call the function-under-test
  TIFF* tiff = TIFFOpenExt(filename.c_str(), mode.c_str(), options);

  // If TIFF* is not null, close it
  if (tiff) {
    TIFFClose(tiff);
  }

  // Free the TIFFOpenOptions
  TIFFOpenOptionsFree(options);

  return 0;
}
