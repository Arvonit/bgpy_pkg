"""
This is an example script to run the simulation configured on the BGPy website in 
Python.

Before running this script, you must have BGPy installed. Instructions can be found 
here: https://github.com/jfuruness/bgpy_pkg/wiki/Installation
"""

import pickle
import yaml
from bgpy.simulation_engine import SimulationEngine
from bgpy.tests.engine_tests.engine_test_configs import config_001
from bgpy.utils import SimulatorCodec, EngineRunner, EngineRunConfig
from pathlib import Path

# We first create an EngineRunner using a YAML dump of the config file generated on
# the website
storage_dir = Path("./engine_local_results")  # Place all engine output here
file = open("./engine_config.yaml", "rb")
config: EngineRunConfig = pickle.load(file)  # Load the config
file.close()
sim = EngineRunner(storage_dir, conf=config_001)  # Create a simulator
engine_local, _, _, _ = sim.run_engine()  # Run the simulation

# We then load the simulation engine from the YAML file to compare to
codec = SimulatorCodec()  # Codec need to parse YAML file
engine_website: SimulationEngine = codec.load(Path("./engine_guess.yaml"))

# Let's check if our simulation worked properly
print(
    "Is our local simulation running correctly? "
    f"{'Yes' if engine_local == engine_website else 'No'}"
)
