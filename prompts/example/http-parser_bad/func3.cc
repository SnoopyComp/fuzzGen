#include "http_parser.h"
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  http_parser parser;
  
  // initialize the parser
  http_parser_init(&parser, HTTP_BOTH);

  if(size >= 1)
  {
    // use first byte to decide value of pause
    int pause = data[0] % 2;
    // call function under test
    http_parser_pause(&parser, pause);
  }

  if (size > 1) {
    http_parser_execute(&parser, NULL, (const char *) (data + 1), size - 1);
  }

  return 0;
}
