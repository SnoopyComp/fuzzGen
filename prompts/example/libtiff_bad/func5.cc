#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <cstdio>
#include <vector>

extern "C" void handle_error(const char *unused, const char *unused2, va_list unused3) { return; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
#ifndef STANDALONE
  TIFFSetErrorHandler(handle_error);
  TIFFSetWarningHandler(handle_error);
#endif
  if (size < 8) {
    // Not enough data to consume an integral and do meaningful work
    return 0;
  }

  FuzzedDataProvider stream(data, size);
  std::vector<uint8_t> buffer(data, data + size);
  std::istringstream s(std::string(reinterpret_cast<const char*>(data), size));
  FILE* tmpFile = tmpfile();
  if (!tmpFile) {
    return 0;
  }

  fwrite(buffer.data(), 1, buffer.size(), tmpFile);
  rewind(tmpFile);

  TIFF *tif = TIFFFdOpen(fileno(tmpFile), "MemTIFF", "r");
  if (!tif) {
    fclose(tmpFile);
    return 0;
  }

  uint64_t subdir_offset = stream.ConsumeIntegral<uint64_t>();
  TIFFSetSubDirectory(tif, subdir_offset);

  TIFFClose(tif);
  fclose(tmpFile);
  return 0;
}

#ifdef STANDALONE

template <class T> static void CPL_IGNORE_RET_VAL(T) {}

static void Usage(int, char *argv[]) {
  fprintf(stderr, "%s [--help] [-repeat N] filename.\n", argv[0]);
  exit(1);
}

int main(int argc, char *argv[]) {
  int nRet = 0;
  void *buf = NULL;
  int nLen = 0;
  int nLoops = 1;
  const char *pszFilename = NULL;

  for (int i = 1; i < argc; i++) {
    if (i + 1 < argc && strcmp(argv[i], "-repeat") == 0) {
      nLoops = atoi(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "-dummy") == 0) {
      uint8_t dummy = ' ';
      return LLVMFuzzerTestOneInput(&dummy, 1);
    } else if (strcmp(argv[i], "--help") == 0) {
      Usage(argc, argv);
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unrecognized option: %s", argv[i]);
      Usage(argc, argv);
    } else {
      pszFilename = argv[i];
    }
  }
  if (pszFilename == nullptr) {
    fprintf(stderr, "No filename specified\n");
    Usage(argc, argv);
  }
  FILE *f = fopen(pszFilename, "rb");
  if (!f) {
    fprintf(stderr, "%s does not exist.\n", pszFilename);
    exit(1);
  }
  fseek(f, 0, SEEK_END);
  nLen = (int)ftell(f);
  fseek(f, 0, SEEK_SET);
  buf = malloc(nLen);
  if (!buf) {
    fprintf(stderr, "malloc failed.\n");
    fclose(f);
    exit(1);
  }
  CPL_IGNORE_RET_VAL(fread(buf, nLen, 1, f));
  fclose(f);
  for (int i = 0; i < nLoops; i++) {
    nRet = LLVMFuzzerTestOneInput(static_cast<const uint8_t *>(buf), nLen);
    if (nRet != 0)
      break;
  }
  free(buf);
  return nRet;
}

#endif
