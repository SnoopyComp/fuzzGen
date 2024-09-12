#include "http_parser.h"
#include <stdint.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  http_parser parser;

  if(size == 0)
    return 0;

  int type = data[0] % 3;
  http_parser_init(&parser, static_cast<http_parser_type>(type));

  size_t rest_size = size - 1;
  const uint8_t *rest = data + 1;
  parser.http_major = rest_size > 0 ? rest[0] : 1;
  parser.http_minor = rest_size > 1 ? rest[1] : 1;
  parser.flags = rest_size > 2 ? rest[2] : 0;
  parser.content_length = rest_size > 3 ? rest[3] : 0;
  parser.http_errno = rest_size > 4 ? static_cast<http_errno>(rest[4] % 48) : HPE_OK;
  parser.upgrade = rest_size > 5 ? rest[5] : 0;
  parser.method = rest_size > 6 ? static_cast<http_method>(rest[6] % 40) : HTTP_GET;

  int should_keep_alive = http_should_keep_alive(&parser);
  
  return 0;
}
