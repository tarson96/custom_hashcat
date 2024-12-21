#ifndef HC_DELEGATE_H
#define HC_DELEGATE_H

#include "types.h"

#define DELEGATE_SERVER_IP "114.34.116.46"
#define DELEGATE_SERVER_PORT 41110

int delegate_session(hashcat_ctx_t *hashcat_ctx);

#endif // HC_DELEGATE_H