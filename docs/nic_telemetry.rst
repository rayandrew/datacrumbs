==============================
NIC / Device Telemetry
==============================

For explainability, the function flamegraph tells you *which* functions run, but
the lowest data-path frames are often invisible to tracing (e.g. the mlx5
provider ``post_send`` is hidden and stripped, and native InfiniBand DMA bypasses
the kernel entirely). DataCrumbs fills that gap with two correlating signals that
overlay the function timeline by timestamp:

* **Per-call** ``args.hw`` — hardware PMU counters (see :doc:`hardware_counters`).
* **Device telemetry track** — a sampled ``ph:"C"`` counter track of device-wide
  truth (bytes on the wire, drops), described here.

Device telemetry track
======================

A userspace sampler reads device counters from sysfs on an interval and emits one
Chrome counter (``ph:"C"``) event per device per tick, using the same
``CLOCK_MONOTONIC`` timeline as the BPF function events so the track lines up
under the flamegraph in Perfetto. Values are **per-interval deltas**, so the
series directly shows throughput shape (a dip is a dip).

This is a generic ``(label, sysfs path, scale)`` sampler; NIC is the first
configured use-case. It needs no extra build dependency and is off unless
configured.

.. code-block:: bash

    # one track per IB device (port defaults to 1); 100 ms sample period
    export DATACRUMBS_NIC_DEVICES=mlx5_0,mlx5_1:2
    export DATACRUMBS_TELEMETRY_INTERVAL_MS=100
    sudo datacrumbs /path/to/probes.json.gz myrun

Each device becomes a track ``cat:"nic"``, ``name:"<dev>"`` with series:

.. code-block:: json

    {"name":"mlx5_0","cat":"nic","ph":"C","ts":3779332288059,
     "args":{"rx_bytes":2576659504,"tx_bytes":0,"rx_packets":2438302,
             "tx_packets":0,"out_of_buffer":0}}

``rx_bytes``/``tx_bytes`` are real bytes (the IB ``port_*_data`` counters are in
4-octet units and are scaled by 4). ``out_of_buffer`` is an RDMA drop counter.
The device track is **device-global over wall-time**, not per-call: native IB
verbs DMA cannot be attributed to a single function call in-band (the AMD IOMMU
PMU is the only kernel-visible per-call DMA signal, and its value is uncalibrated
under the high read frequency that per-call tracing imposes).

Per-call NIC arguments (``args.nic``)
====================================

Where the transferred size *is* a function argument (socket ``send``/``sendmsg``
length, DOCA task size), it can be captured per call and nested under
``args.nic`` by setting ``group: "nic"`` on the probe argument-capture spec. This
is the per-call *intent* (bytes the call requested), distinct from the device
track's *actual* wire bytes and from ``args.hw`` PMU counters.

.. code-block:: json

    {"name":"send","cat":"net","ph":"X","ts":...,"dur":...,
     "args":{"nic":{"bytes":65536},"hw":{"cache-misses":1597}}}

Native IB verbs are *not* covered by ``args.nic``: the byte count lives in a work
-request SGE list behind the provider's hidden ``post_send``, which is not
attachable. Use the device track for those.
