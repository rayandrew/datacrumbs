import logging

import hydra
from omegaconf import DictConfig

from datacrumbs.common.status import ProfilerStatus
from datacrumbs.configs.configuration_manager import ConfigurationManager
from datacrumbs.dfbcc.dfbcc import BCCMain, StopExecution


class Datacrumbs:
    """
    Datacrumbs Class
    """

    def __init__(self, cfg: DictConfig) -> None:
        self.config = ConfigurationManager.get_instance().load(cfg)

    def initialize(self) -> None:
        self.bcc = BCCMain().load()

    def run(self) -> None:
        self.bcc.run()

    def finalize(self) -> None:
        logging.info("Detaching...")


@hydra.main(version_base=None, config_path="configs", config_name="config")
def main(cfg: DictConfig) -> int:
    """
    The main method to start the profiler runtime.
    """
    profiler = Datacrumbs(cfg["module"])
    profiler.initialize()
    try:
        profiler.run()
    except StopExecution:
        logging.info("Stopping execution...")
    finally:
        profiler.finalize()
    return ProfilerStatus.SUCCESS


if __name__ == "__main__":
    status: int = main()
    exit(status)
