#include "http_parser.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(int))
    return 0;

  int enum_value = *((int*) data);

  // Enum http_errno ranges from 0 to 20 (inclusive).
  // Ignore out-of-range values.
  if (enum_value < 0 || enum_value > 20)
    return 0;
    
  const char *desc = http_errno_description((enum http_errno)enum_value);
  if (desc == NULL)
    return 0;

  return 0;
}
