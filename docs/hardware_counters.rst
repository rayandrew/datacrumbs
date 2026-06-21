==============================
Hardware PMU Counters
==============================

DataCrumbs can attach hardware performance-monitoring counters (PMU events such
as cache-misses, instructions, branch-misses) to each traced function call. The
counter is snapshotted at function entry and again at exit; the **delta** (work
done by that one call) rides **in the same per-call trace record** as the
duration — there is no separate event stream and no sampling.

The counters appear under a nested ``hw`` object inside the event ``args`` (so
they never collide with captured function arguments):

.. code-block:: json

    {"name":"work","cat":"hwctest","ph":"X","ts":3773459810020,"dur":432,
     "pid":272662,"tid":272662,
     "args":{"hw":{"branch-misses":239,"cache-misses":1597,"instructions":2626471}}}

A cpu migration between entry and exit adds ``"migrated":1`` inside ``hw``.

This is per-invocation, not periodic: one record per real entry/exit, at
whatever rate the application calls the function.

Enabling the feature (build time)
=================================

Hardware counters are an **opt-in** build option so that ``libpfm4`` stays an
optional dependency. With the feature OFF (the default) the event layout is
byte-for-byte unchanged and ``libpfm4`` is not linked.

.. code-block:: bash

    cmake -DDATACRUMBS_ENABLE_HW_COUNTERS_OPT=ON ...        # enable
    # optional: number of counter slots compiled into the record (default 6)
    cmake -DDATACRUMBS_ENABLE_HW_COUNTERS_OPT=ON -DDATACRUMBS_HW_COUNTER_SLOTS=6 ...

``DATACRUMBS_HW_COUNTER_SLOTS`` is the compile-time **capacity** of the event
record; the runtime selects how many of those slots to use (see below). It does
not need changing for normal use.

Requires `libpfm4 <https://perfmon2.sourceforge.net/>`_ (``perfmon/pfmlib.h`` +
``libpfm``) on the build/run host.

Selecting events (run time)
===========================

Which counters to read is chosen per run via the ``DATACRUMBS_HW_COUNTERS``
environment variable: a comma-separated list of `libpfm4` event names.

.. code-block:: bash

    export DATACRUMBS_HW_COUNTERS=cache-misses,instructions,branch-misses
    sudo datacrumbs /path/to/probes.json.gz myrun

* **Unset** → defaults to ``cache-misses``.
* **Empty** (``DATACRUMBS_HW_COUNTERS=``) → no counters.
* **Custom list** → those events, in order.

Event names are resolved by ``libpfm4`` (PAPI-grade naming, vendor-neutral:
AMD / Intel / ARM). Generic names like ``cache-misses``, ``instructions``,
``branch-misses``, ``cycles`` work across PMUs; native names (e.g.
``amd64_fam19h_zen4::RETIRED_SSE_AVX_FLOPS:ANY`` for per-function FLOPs) are also
accepted. List available events with libpfm4's ``showevtinfo``.

How many counters at once
=========================

The number of counters that can run **simultaneously without multiplexing** is
limited by the CPU's general-purpose PMU counters (e.g. 6 on AMD Zen4, minus one
if the NMI watchdog is enabled → 5 usable; often 4 on Intel cores). Requesting
more than the hardware budget makes the kernel time-slice the counters, and the
per-call delta becomes unreliable. Keep the list within that budget (and within
``DATACRUMBS_HW_COUNTER_SLOTS``). When multiplexing is detected, the record also
exposes ``<event>.enabled`` / ``<event>.running`` so the value can be scaled.

For many metrics, run the workload multiple times with different event sets.

Correctness notes
==================

* **Pin your threads** (e.g. ``taskset``). If a thread migrates CPUs between
  entry and exit, the entry/exit counter reads are on different cores and the
  delta is meaningless. DataCrumbs detects this and adds ``"hwc_migrated":1`` to
  the record so such samples can be filtered.
* **perf access**: per-CPU counters require ``perf_event_paranoid <= 0`` or
  ``CAP_PERFMON`` / root. DataCrumbs already runs the tracer as root; if
  ``perf_event_open`` still fails, check
  ``/proc/sys/kernel/perf_event_paranoid`` and that the PMU exposes the event.
* Some generalized cache events (e.g. ``LLC-load-misses`` on certain AMD PMUs)
  encode but fail to open per-task because they live in an uncore PMU; prefer
  core-PMU events or vendor-native names. Failures are reported clearly at
  startup rather than producing bogus data.

Scope
=====

Counters are captured for kprobe, uprobe, syscall, and USDT entry/exit pairs in
tracer mode. NIC-level metrics are a different domain: per-call bytes are best
captured via argument capture on the network/DOCA calls, and device-global NIC
telemetry (IOMMU/ethtool) as a separate counter track — neither consumes the
per-call PMU slots described here.
