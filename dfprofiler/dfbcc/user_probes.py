from typing import *
import os
import logging
from bcc import BPF
from dfprofiler.dfbcc.collector import BCCCollector
from dfprofiler.dfbcc.probes import BCCFunctions, BCCProbes
from dfprofiler.common.enumerations import ProbeType
from dfprofiler.configs.configuration_manager import ConfigurationManager


class UserProbes:
    config: ConfigurationManager
    probes: List[BCCProbes]

    def __init__(self) -> None:
        self.config = ConfigurationManager.get_instance()
        self.probes = []
        for key, obj in self.config.user_libraries.items():
            probe = BCCProbes(ProbeType.USER, key, [])
            if "regex" not in obj:
                symbols = (
                    os.popen(f"nm {obj['name']} | grep \" T \" | awk {{'print $3'}}")
                    .read()
                    .strip()
                    .split("\n")
                )
                for symbol in symbols:
                    if symbol or symbol != "":
                        probe.functions.append(BCCFunctions(symbol))
                        logging.debug(f"Adding Probe function {symbol} from {key}")
            else:
                probe.functions.append(BCCFunctions(obj["name"], obj["regex"]))
                logging.debug(
                    f"Adding Probe function {obj['regex']} from {obj['name']}"
                )

            self.probes.append(probe)

    def collector_fn(self, collector: BCCCollector, category_fn_map, count: int):
        bpf_text = ""
        for probe in self.probes:
            for fn in probe.functions:
                count = count + 1
                text = collector.get_wrapper_functions()
                text = text.replace("DFCAT", probe.category)
                text = text.replace("DFFUNCTION", fn.name)
                text = text.replace("DFEVENTID", str(count))
                category_fn_map[count] = (probe.category, fn)
                bpf_text += text

        return (bpf_text, category_fn_map, count)

    def attach_probes(self, bpf: BPF, collector: BCCCollector) -> None:

        for probe in self.probes:

            for fn in probe.functions:
                try:
                    logging.debug(
                        f"Adding Probe function {fn.name} from {probe.category}"
                    )
                    if ProbeType.SYSTEM == probe.type:
                        fnname = bpf.get_syscall_prefix().decode() + fn.name
                        bpf.attach_kprobe(
                            event_re=fnname,
                            fn_name=f"trace_{probe.category}_{fn.name}_entry",
                        )
                        bpf.attach_kretprobe(
                            event_re=fnname,
                            fn_name=f"trace_{probe.category}_{fn.name}_exit",
                        )
                    elif ProbeType.KERNEL == probe.type:
                        bpf.attach_kprobe(
                            event_re=fn.name,
                            fn_name=f"trace_{probe.category}_{fn.name}_entry",
                        )
                        bpf.attach_kretprobe(
                            event_re=fn.name,
                            fn_name=f"trace_{probe.category}_{fn.name}_exit",
                        )
                    elif ProbeType.USER == probe.type:
                        library = probe.category
                        fname = fn.name
                        is_regex = False
                        if fn.regex:
                            is_regex = True
                            fname = fn.regex
                        if probe.category in self.config.user_libraries:
                            library = self.config.user_libraries[probe.category]["link"]
                            bpf.add_module(library)

                        if is_regex:
                            bpf.attach_uprobe(
                                name=library,
                                sym_re=fname,
                                fn_name=f"trace_{probe.category}_{fn.name}_entry",
                            )
                            bpf.attach_uretprobe(
                                name=library,
                                sym_re=fname,
                                fn_name=f"trace_{probe.category}_{fn.name}_exit",
                            )
                        else:
                            bpf.attach_uprobe(
                                name=library,
                                sym=fname,
                                fn_name=f"trace_{probe.category}_{fn.name}_entry",
                            )
                            bpf.attach_uretprobe(
                                name=library,
                                sym=fname,
                                fn_name=f"trace_{probe.category}_{fn.name}_exit",
                            )
                except Exception as e:
                    logging.warn(
                        f"Unable attach probe {probe.category} to user function {fn.name} due to {e}"
                    )
