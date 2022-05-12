#ifndef DEMO_LOG_H
#define DEMO_LOG_H

#define ERR(_fmt, ...)                                                        \
  fprintf(stderr, "%s():%u: " _fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG(_fmt, ...)                                                        \
  fprintf(stdout, "%s():%u: " _fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#ifndef NDEBUG
#define DBG_DEF(...) __VA_ARGS__
#define DBG(_fmt, ...) \
  fprintf(stdout, "%s():%u: " _fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else /* NDEBUG */
#define DBG(...)
#define DBG_DEF(...)
#endif

#endif
