/*!
 * @file sukat_util.h
 * @brief Random utility functions
 *
 * @addtogroup sukat_util
 * @{
 *
 */
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netdb.h>
#include <stdlib.h>

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
          fprintf(output, "    -%c,--%s %s %s\n", opts[i].val, opts[i].name,
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

__int128 sukat_util_ntohlll(__int128 orig)
{
  union
    {
      __int128 value;
      uint32_t val4[4];
    } ret, src;

  src.value = orig;

  ret.val4[0] = ntohl(src.val4[3]);
  ret.val4[1] = ntohl(src.val4[2]);
  ret.val4[2] = ntohl(src.val4[1]);
  ret.val4[3] = ntohl(src.val4[0]);

  return ret.value;
}

static void copy_ip_agnostic_to_variable(int family, uint32_t *target_ipv4,
                                         __int128 *target_ipv6,
                                         struct sockaddr *src)
{
  if (family == AF_INET)
    {
      *target_ipv4 = ((struct sockaddr_in *)(src))->sin_addr.s_addr;
      *target_ipv4 = ntohl(*target_ipv4);
    }
  else
    {
      memcpy(target_ipv6, &((struct sockaddr_in6 *)(src))->sin6_addr,
             sizeof(*target_ipv6));
      *target_ipv6 = sukat_util_ntohlll(*target_ipv6);
    }
}

static bool range_integer(const char *range,
                          struct sukat_util_range_values *values)
{
  const char *delimiter = strchr(range, '-');
  char buf[INET6_ADDRSTRLEN] = {};
  long long val, val_end;
  ;

  strncat(buf, range, delimiter ? delimiter - range : strlen(range));
  val = atoll(buf);
  if (delimiter)
    {
      val_end = atoll(delimiter + 1);
    }
  else
    {
      val_end = val;
    }

  if (val > UINT32_MAX || val_end > UINT32_MAX)
    {
      values->start16 = val;
      values->end16 = val_end;
      values->count16 = val_end - val;
      values->type = SUKAT_UTIL_RANGE_VALUE_16BYTE;
    }
  else
    {
      values->start4 = val;
      values->end4 = val_end;
      if (val_end == val)
        {
          values->count4 = 1;
        }
      else
        {
          values->count4 = val_end - val;
        }
      values->type = SUKAT_UTIL_RANGE_VALUE_4BYTE;
    }
  return true;
}

static bool range_ip(const char *range, struct sukat_util_range_values *values)
{
  const char *delimiter = strchr(range, '-');
  char buf[INET6_ADDRSTRLEN] = {};
  bool bret = false;
  struct addrinfo hints = {.ai_family = AF_UNSPEC,
                           .ai_flags = AI_PASSIVE | AI_NUMERICHOST},
                  *result;
  int ret;

  strncat(buf, range, delimiter ? delimiter - range : strlen(range));
  if (!(ret = getaddrinfo(buf, "179", &hints, &result)))
    {
      int family;

      copy_ip_agnostic_to_variable(result->ai_family, &values->start4,
                                   &values->start16, result->ai_addr);
      family = result->ai_family;
      freeaddrinfo(result);
      if (delimiter)
        {
          ret = getaddrinfo(delimiter + 1, "179", &hints, &result);
          if (!ret)
            {
              copy_ip_agnostic_to_variable(result->ai_family, &values->end4,
                                           &values->end16, result->ai_addr);
              bret = true;
              switch (family)
                {
                  case AF_INET:
                    values->count4 = values->end4 - values->start4;
                    values->type = SUKAT_UTIL_RANGE_VALUE_4BYTE;
                    break;
                  case AF_INET6:
                    values->count16 = values->end16 - values->start16;
                    values->type = SUKAT_UTIL_RANGE_VALUE_16BYTE;
                    break;
                }
              freeaddrinfo(result);
            }
        }
      else
        {
          bret = true;
          switch (family)
            {
              case AF_INET:
                values->count4 = 1;
                values->type = SUKAT_UTIL_RANGE_VALUE_4BYTE;
                break;
              case AF_INET6:
                values->count16 = 1;
                values->type = SUKAT_UTIL_RANGE_VALUE_16BYTE;
                break;
            }
        }
    }
  return bret;
}

bool sukat_util_range_to_integers(const char *range,
                                  enum sukat_util_range_input_type type,
                                  struct sukat_util_range_values *values)
{
  bool bret = false;

  if (range)
    {
      switch (type)
        {
        case SUKAT_UTIL_RANGE_INPUT_INTEGER:
          bret = range_integer(range, values);
          break;
        case SUKAT_UTIL_RANGE_INPUT_IP:
          bret = range_ip(range, values);
          break;
        default:
          break;
        }
    }
  return bret;
}

bool sukat_util_file_limit_increase(const unsigned int minimum)
{
  struct rlimit limits;

  if (!getrlimit(RLIMIT_NOFILE, &limits))
    {
      if (limits.rlim_cur < minimum * 2)
        {
          limits.rlim_cur = limits.rlim_max = minimum * 2;

          if (!setrlimit(RLIMIT_NOFILE, &limits))
            {
              return true;
            }
        }
      else
        {
          return true;
        }
    }
  return false;
}

/*! @} */
