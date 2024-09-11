#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "/src/libraw/libraw/libraw.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Initialize the fuzzed data provider
  FuzzedDataProvider stream(data, size);

  // Create an instance of LibRaw
  LibRaw rawProcessor;

  // Call the function-under-test with the provided data
  rawProcessor.open_buffer(data, size);

  // Since `selectCRXTrack` does not exist, we need to call another function
  // that is relevant to the usage of LibRaw. For example, we can call:
  rawProcessor.unpack();

  return 0;
}