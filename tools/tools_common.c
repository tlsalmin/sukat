#include "tools_common.h"

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tools_log.h"

unsigned long long safe_unsigned(const char *value_in_ascii, long long max_size)
{
  long long val = atoll(value_in_ascii);

  if (val < 0 || val > max_size)
    {
      ERR("Too big or negative argument %s", value_in_ascii);
      exit(EXIT_FAILURE);
    }

  return (unsigned long long)val;
}

int simple_sighandler(const sigset_t *additional_signals)
{
  sigset_t sigs_temp, sigs;

  sigemptyset(&sigs_temp);
  sigemptyset(&sigs);
  sigaddset(&sigs_temp, SIGTERM);
  sigaddset(&sigs_temp, SIGINT);
  sigorset(&sigs, &sigs_temp, additional_signals);

  if (!sigprocmask(SIG_BLOCK, &sigs, &sigs_temp))
    {
      int ret = signalfd(-1, &sigs, SFD_NONBLOCK | SFD_CLOEXEC);
      if (ret != -1)
        {
          LOG("Created signalfd %d", ret);
          return ret;
        }
      else
        {
          ERR("Failed to create signalfd: %m");
        }
      sigprocmask(SIG_BLOCK, &sigs_temp, NULL);
    }
  else
    {
      ERR("Failed to block signals: %m");
    }
  return -1;
}

int simple_sighandler_read_signal(int sigfd)
{
  struct signalfd_siginfo sinfo;
  int ret = read(sigfd, &sinfo, sizeof(sinfo));

  if (ret == sizeof(sinfo))
    {
      LOG("Received signal %s", strsignal(sinfo.ssi_signo));

      return sinfo.ssi_signo;
    }
  if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
      return 0;
    }
  else
    {
      ERR("Failed to read signalfd: %m");
    }
  return -1;
}

