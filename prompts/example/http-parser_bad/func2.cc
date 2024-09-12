#include "http_parser.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) return 0;
  enum http_errno err_no = *data % 20; // Replaced HTTP_ERRNO_MAX with its actual value 20
  const char * name = http_errno_name(err_no);
  return 0;
}
