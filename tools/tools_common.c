#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include "tools_log.h"

bool keep_running;

unsigned long long safe_unsigned(char *value_in_ascii, long long max_size)
{
  long long val = atoll(value_in_ascii);

  if (val < 0 || val > max_size)
    {
      ERR("Too big or negative argument %s", value_in_ascii);
      exit(EXIT_FAILURE);
    }

  return (unsigned long long)val;
}

static void sighandler(int siggie)
{
  LOG("Received signal %d", siggie);
  keep_running = false;
}

bool simple_sighandler()
{
  struct sigaction new_action =
    {
      .sa_handler = sighandler,
    };

  if (sigaction(SIGINT, &new_action, NULL))
    {
      ERR("Failed to set signal handler: %s", strerror(errno));
      return false;
    }
  return true;
}


