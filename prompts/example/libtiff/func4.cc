#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider stream(data, size);

  // Generate a filename and mode string
  std::string filename = stream.ConsumeRandomLengthString(100);
  std::string mode = stream.ConsumeRandomLengthString(10);

  // Ensure filename and mode are not empty
  if (filename.empty() || mode.empty()) {
    return 0;
  }

  // Create default TIFFOpenOptions
  TIFFOpenOptions* options = TIFFOpenOptionsAlloc();

  // Call TIFFOpenExt
  TIFF* tiff = TIFFOpenExt(filename.c_str(), mode.c_str(), options);

  // If TIFF* is not null, close it
  if (tiff) {
    TIFFClose(tiff);
  }

  // Free the TIFFOpenOptions
  TIFFOpenOptionsFree(options);

  return 0;
}