/*!
 * @file sukat_util.h
 * @brief Random utility functions
 *
 * @addtogroup sukat_util
 * @{
 *
 */
#include <fcntl.h>

#include "sukat_util.h"

void sukat_util_usage(const struct option *opts, const char **explanations,
                      FILE *output)
{
  if (output && opts && explanations)
    {
      unsigned int i;

      fprintf(stdout, "Options: \n");
      for (i = 0; opts[i].name; i++)
        {
          char optstring[] = "[<arg>]";

          if (opts[i].has_arg == required_argument)
            {
              snprintf(optstring, sizeof(optstring), "<arg>");
            }
          else if (opts[i].has_arg == no_argument)
            {
              optstring[0] = '\0';
            }
          fprintf(output, "    -%c,%s %s %s\n", opts[i].val, opts[i].name,
                  optstring, explanations[i]);
        }
    }
}

int sukat_util_flagit(int fd)
{
  int flags;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0)
    {
      flags |= O_NONBLOCK;
      if (fcntl(fd, F_SETFL, flags) == 0)
        {
          flags = fcntl(fd, F_GETFD, 0);
          if (flags >= 0)
            {
              flags |= FD_CLOEXEC;
              if (fcntl(fd, F_SETFD, flags) == 0)
                {
                  return 0;
                }
            }
        }
    }
  return -1;
}

/*! @} */
