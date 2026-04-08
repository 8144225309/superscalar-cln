/* Fee estimator stubs for the CLN plugin.
 *
 * libsuperscalar's factory.c needs fee_for_factory_tx() and
 * fee_should_use_anchor() for tree transaction construction.
 * CLN handles actual fee estimation; these provide sensible defaults. */

#include <stdint.h>
#include <stddef.h>

typedef struct fee_estimator fee_estimator_t;

uint64_t fee_for_factory_tx(fee_estimator_t *fe, size_t n_outputs)
{
	(void)fe;
	/* ~68 vB overhead + 43 vB per P2TR output at 10 sat/vB */
	return (68 + 43 * n_outputs) * 10;
}

int fee_should_use_anchor(fee_estimator_t *fe)
{
	(void)fe;
	return 1; /* always include P2A anchor */
}
