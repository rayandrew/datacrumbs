#ifndef __DATACRUMBS_COMMON_CONSTANTS_H
#define __DATACRUMBS_COMMON_CONSTANTS_H
#define DATACRUMBS_PROBE_CATEGORY "DC"
#define START_FUNCTION_NAME "start"
#define START_EVENT_ID 1
#define END_FUNCTION_NAME "end"
#define END_EVENT_ID 2
#ifndef DATACRUMBS_MAX_PMU
#define DATACRUMBS_MAX_PMU 3  // max hardware counters read per event (entry/exit delta)
#endif
#endif  // __DATACRUMBS_COMMON_CONSTANTS_H