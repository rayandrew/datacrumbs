from enum import IntEnum


class ProfilerStatus(IntEnum):
    """
    Different status codes for the profiler.
    """

    SUCCESS = 0
    SYSTEM_FAIL = -1
    CONVERT_ERROR = 1000

    def success(self):
        return self.value == ProfilerStatus.SUCCESS.value

    def failed(self):
        return self.value != ProfilerStatus.SUCCESS.value
