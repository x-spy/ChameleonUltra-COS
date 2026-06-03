#ifndef COS_HOST_STUB_APP_UTIL_H
#define COS_HOST_STUB_APP_UTIL_H

#define PACKED __attribute__((packed))
#define STATIC_ASSERT(cond) typedef char static_assertion_##__LINE__[(cond) ? 1 : -1]
#define UNUSED_PARAMETER(x) (void)(x)

#endif
