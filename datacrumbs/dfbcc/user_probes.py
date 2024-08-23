import logging
import os
import re
from typing import List

from bcc import BPF

from datacrumbs.common.enumerations import ProbeType
from datacrumbs.configs.configuration_manager import ConfigurationManager
from datacrumbs.dfbcc.collector import BCCCollector
from datacrumbs.dfbcc.probes import BCCFunctions, BCCProbes


class UserProbes:
    config: ConfigurationManager
    probes: List[BCCProbes]

    def __init__(self) -> None:
        self.config = ConfigurationManager.get_instance()
        self.probes = []
        for key, obj in self.config.user_libraries.items():
            probe = BCCProbes(ProbeType.USER, key, [])
            if "regex" not in obj:
                pattern = re.compile(".*")
            else:
                pattern = re.compile(obj["regex"])  # type: ignore
            link = obj["link"]  # type: ignore
            symbols = os.popen(f"nm {link} | grep \" T \" | awk {{'print $3'}}").read().strip().split("\n")
            for symbol in symbols:
                if (symbol or symbol != "") and pattern.match(symbol):
                    probe.functions.append(BCCFunctions(symbol))
                    logging.debug(f"Adding Probe function {symbol} from {key}")
            self.probes.append(probe)

    def collector_fn(self, collector: BCCCollector, category_fn_map, count: int):
        bpf_text = ""
        for probe in self.probes:
            for fn in probe.functions:
                count = count + 1
                if ProbeType.SYSTEM == probe.type:
                    text = collector.sys_functions
                else:
                    text = collector.functions
                text = text.replace("DFCAT", probe.category)
                text = text.replace("DFFUNCTION", fn.name)
                text = text.replace("DFEVENTID", str(count))
                text = text.replace("DFENTRYCMD", fn.entry_cmd)
                text = text.replace("DFEXITCMDSTATS", fn.exit_cmd_stats)
                text = text.replace("DFEXITCMDKEY", fn.exit_cmd_key)
                text = text.replace("DFENTRYARGS", fn.entry_args)
                category_fn_map[count] = (probe.category, fn)
                bpf_text += text

        return (bpf_text, category_fn_map, count)

    def attach_probes(self, bpf: BPF, collector: BCCCollector) -> None:
        for probe in self.probes:
            for fn in probe.functions:
                try:
                    if ProbeType.USER == probe.type:
                        logging.debug(f"Adding Probe function {fn.name} from {probe.category}")
                        library = probe.category
                        fname = fn.name
                        if probe.category in self.config.user_libraries:
                            library = self.config.user_libraries[probe.category]["link"]  # type: ignore
                            bpf.add_module(library)
                        bpf.attach_uprobe(
                            name=library.encode(),
                            sym=fname.encode(),
                            fn_name=f"trace_{probe.category}_{fn.name}_entry".encode(),
                        )
                        bpf.attach_uretprobe(
                            name=library.encode(),
                            sym=fname.encode(),
                            fn_name=f"trace_{probe.category}_{fn.name}_exit".encode(),
                        )
                except Exception as e:
                    logging.warning(f"Unable attach probe {probe.category} to user function {fn.name} due to {e}")

    def detach_probes(self, bpf: BPF, collector: BCCCollector) -> None:
        for probe in self.probes:
            for fn in probe.functions:
                try:
                    if ProbeType.USER == probe.type:
                        library = probe.category
                        fname = fn.name
                        if probe.category in self.config.user_libraries:
                            library = self.config.user_libraries[probe.category]["link"]  # type: ignore
                        bpf.detach_uprobe(name=library.encode(), sym=fname.encode())
                        bpf.detach_uretprobe(name=library.encode(), sym=fname.encode())
                except:
                    logging.warning(f"Unable to detach probe {probe.category} to user function {fn.name}")
