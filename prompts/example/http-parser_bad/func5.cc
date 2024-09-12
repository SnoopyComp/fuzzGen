#include "http_parser.h"
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;
  
  enum http_status status = data[0] % (HTTP_STATUS_OK + 1);
  http_status_str(status);

  return 0;
}
