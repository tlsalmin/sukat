/*!
 * @file sukat_dns.h
 * @brief DNS library.
 *
 * @defgroup sukat_dns
 * @ingroup sukat_api
 * @{
 *
 */

#ifndef SUKAT_DNS_H
#define SUKAT_DNS_H

#include <stdbool.h>
#include "sukat_log.h"

/*!
 * @brief Callback for a solved DNS query.
 *
 * @param caller_ctx    Caller context given by user
 * @param target        Target given to original query in \ref sukat_dns_solve
 * @param result        If non-null, succesfully queried IP for \p target
 */
typedef void (*sukat_dns_solved_cb)(char *caller_ctx, const char *target,
                                    const char *result);

struct sukat_dns_cbs
{
  sukat_log_cb log_cb;
  sukat_dns_solved_cb solved_cb;
};

struct sukat_dns_params
{
  void *caller_ctx; //!< Context given by default to solved_cb
};

typedef struct sukat_dns_ctx sukat_dns_t;

/*!
 * @brief Create a sukat DNS context.
 *
 * @param params        Parameters for DNS context.
 * @param cbs           Callbacks for DNS context.
 *
 * @return != NULL      Sukat DNS context.
 * @return NULL         Failure.
 */
sukat_dns_t *sukat_dns_create(struct sukat_dns_params *params,
                              struct sukat_dns_cbs *cbs);

/*!
 * @brief Query \p target IP-address.
 *
 * @param ctx           DNS context.
 * @param query_specific_caller_ctx Optional query specific context given in
 *                                  \ref sukat_dns_solved_cb
 * @param target        Target to solve.
 *
 * @return true         Query under way.
 * @return false        Sending / Creating query failed.
 */
bool sukat_dns_query(sukat_dns_t *ctx, void *query_specific_caller_ctx,
                     const char *target);

/*!
 * @brief Destroy DNS context.
 *
 * @param ctx   Context to destroy
 */
void sukat_dns_destroy(sukat_dns_t *ctx);

#endif /* SUKAT_DNS_H */

/*! @} */
