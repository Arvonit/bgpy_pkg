from lib_caida_collector import CaidaCollector
from datetime import datetime
from pathlib import Path
import logging
import shutil

from .diagram import Diagram
from .simulator_codec import SimulatorCodec
from ..conftest import PytestOptions
from ...engine import SimulatorEngine
from ...simulator import Scenario


class YamlSystemTestRunner:

    def __init__(self, dir_, preloaded_engine=None, preloaded_engine_input=None):
        """dir_ should be the dir_ with the yaml"""

        self.dir_ = dir_
        self.codec = SimulatorCodec()
        self.preloaded_engine = preloaded_engine
        self.preloaded_engine_input = preloaded_engine_input

    def run_test(self, empty_engine_kwargs, engine_input_kwargs):

        preloaded = self.preloaded_engine and self.preloaded_engine_input

        if preloaded:
            engine = self.preloaded_engine
            engine_input = self.preloaded_engine_input
        else:
            engine, engine_input = self.write_load_engine(empty_engine_kwargs,
                                                          engine_input_kwargs)

        scenario, engine_traceback_guess = self.get_results(engine,
                                                         engine_input,
                                                         empty_engine_kwargs["BaseASCls"],
                                                         preloaded=preloaded)

        try:
            self.write_check_results(engine, scenario, engine_traceback_guess)
            self.write_diagrams(engine, engine_traceback_guess, engine_input)
        except Exception as e:
            self.write_diagrams(engine, engine_traceback_guess, engine_input)
            raise e

        return engine, engine_input, scenario, engine_traceback_guess


    def write_load_engine(self, empty_engine_kwargs, engine_input_kwargs):

        # Write the graph if it does not exist
        if not self.empty_engine_yaml_path.exists():
            self.write_empty_engine_yaml(**empty_engine_kwargs)

        if not self.engine_input_yaml_path.exists():
            self.write_engine_input_yaml(**engine_input_kwargs)

        return self.load_engine_and_input()

    def load_engine_and_input(self):
        engine = self.codec.load(self.empty_engine_yaml_path)
        engine_input = self.codec.load(self.engine_input_yaml_path)
        return engine, engine_input

    def get_results(self, engine, engine_input, BaseASCls, preloaded=False):

        if not preloaded:
            engine.setup(engine_input, BaseASCls, None)

        scenario = Scenario(engine=engine, engine_input=engine_input)
        subgraphs = {"all_ases": set([x.asn for x in engine])}

        # 0 for the propagation round. Change this later
        traceback_guess = scenario.run(subgraphs, 0)

        return scenario, traceback_guess

    def write_diagrams(self, engine_guess, engine_output_guess, engine_input):
        """Write diagrams for both guess and ground truth"""

        # Diagram for guess
        Diagram().generate_as_graph(engine_guess,
                                    engine_output_guess,
                                    engine_input,
                                    path=self.engine_output_guess_gv_path,
                                    view=PytestOptions.view)


        engine_truth = self.codec.load(path=self.engine_output_truth_yaml_path)
        traceback_truth = self.codec.load(path=self.traceback_truth_yaml_path)

        # Diagram for ground truth
        Diagram().generate_as_graph(engine_truth,
                                    traceback_truth,
                                    engine_input,
                                    path=self.engine_output_truth_gv_path,
                                    view=PytestOptions.view)

    def write_check_results(self, engine, scenario, traceback_guess):
        if not self.engine_output_guess_yaml_path.exists():
            self.write_engine_output_yaml(engine)
            if PytestOptions.write_no_verify:
                logging.warning("Writing engine output ground truth without verifying")
                shutil.copy(self.engine_output_guess_yaml_path,
                            self.engine_output_truth_yaml_path)

        if not self.traceback_guess_yaml_path.exists():
            self.write_traceback_yaml(traceback_guess)
            if PytestOptions.write_no_verify:
                logging.warning("Writing traceback ground truth without verifying")
                shutil.copy(self.traceback_guess_yaml_path,
                            self.traceback_truth_yaml_path)

        self.validate_engine_output(engine)
        self.validate_scenario(scenario)
        self.validate_traceback_guess(traceback_guess)

    def write_empty_engine_yaml(self,
                                customer_provider_links: set = None,
                                peer_links: set = None,
                                BaseASCls=None,
                                ixps=set(),
                                input_clique=set()):
        """Writes yaml empty engine graph"""

        engine = SimulatorEngine(customer_provider_links,
                                 peer_links,
                                 BaseASCls=BaseASCls,
                                 ixps=ixps,
                                 input_clique=input_clique)
        self.codec.dump(engine, path=self.empty_engine_yaml_path)

    def write_engine_input_yaml(self,
                                EngineInputCls=None,
                                attacker_asn=None,
                                victim_asn=None,
                                as_classes: dict = None):
        """Writes engine input yaml"""

        engine_input = EngineInputCls(attacker_asn=attacker_asn,
                                      victim_asn=victim_asn,
                                      as_classes=as_classes)
        self.codec.dump(engine_input, path=self.engine_input_yaml_path)

    def write_engine_output_yaml(self, engine):
        logging.warning("Writing unverified engine output yaml. Must be verified and copied to ground truth")
        self.codec.dump(engine, path=self.engine_output_guess_yaml_path)

    def write_traceback_yaml(self, traceback_output: dict):
        logging.warning("Writing unverified traceback yaml. Must be verified and copied to ground truth")
        self.codec.dump(traceback_output, path=self.traceback_guess_yaml_path)

    def validate_engine_output(self, engine):
        engine_guess = self.codec.load(self.engine_output_guess_yaml_path)
        try:
            engine_ground_truth = self.codec.load(self.engine_output_truth_yaml_path)
        except FileNotFoundError:
            raise NotImplementedError("No ground truth yaml file. Must copy guess and verify")

        assert engine_guess == engine_ground_truth

    def validate_scenario(self, scenario):
        pass

    def validate_traceback_guess(self, traceback_guess):
        traceback_guess = self.codec.load(self.traceback_guess_yaml_path)
        try:
            traceback_ground_truth = self.codec.load(self.traceback_truth_yaml_path)
        except FileNotFoundError:
            raise NotImplementedError("No ground truth yaml file. Must copy guess and verify")

        assert traceback_guess == traceback_ground_truth

    @property
    def empty_engine_yaml_path(self):
        return self.dir_ / "empty_engine_graph.yaml"

    @property
    def engine_input_yaml_path(self):
        return self.dir_ / "engine_input.yaml"

    @property
    def engine_output_truth_yaml_path(self):
        return self.dir_ / "engine_output_ground_truth.yaml"

    @property
    def engine_output_truth_gv_path(self):
        return self.dir_ / "engine_output_ground_truth.gv"

    @property
    def traceback_truth_yaml_path(self):
        return self.dir_ / "engine_traceback_ground_truth.yaml"

    @property
    def engine_output_guess_yaml_path(self):
        return self.dir_ / "engine_output_guess.yaml"

    @property
    def engine_output_guess_gv_path(self):
        return self.dir_ / "engine_output_guess.gv"

    @property
    def traceback_guess_yaml_path(self):
        return self.dir_ / "engine_traceback_guess.yaml"