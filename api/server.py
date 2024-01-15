from dataclasses import replace
import os
import uvicorn
import pickle
import tempfile
from pathlib import Path
from typing import Any, Sequence

# from bgpy.simulation_frameworks.cpp_simulation_framework.cpp_as_graph_analyzer import (
#     CPPASGraphAnalyzer,
# )
# from bgpy.tests.engine_tests.engine_test_configs import config_001
# from bgpy.enums import PyRelationships, CPPRelationships  # type: ignore
# from bgpy.simulation_engines.cpp_simulation_engine import (
#     CPPSimulationEngine,
#     CPPAnnouncement,  # type: ignore
# )
from config import Config
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from tempfile import TemporaryDirectory, TemporaryFile
from pydantic import ValidationError

from bgpy.utils import EngineRunner
from zipfile import ZipFile

app = FastAPI()
origins = [
    "http://localhost:5173",
    "localhost:5173",
    "https://bgpy.uconn.edu",
    "http://bgpy.uconn.edu",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
temp_dir = TemporaryDirectory()


@app.post("/simulate")
async def simulate(config: Config, download_zip: bool = False):
    # TODO: Check JSON file size to ensure graph isn't too big
    # https://github.com/tiangolo/fastapi/issues/362
    erc = config.to_engine_run_config()
    # erc = replace(
    #     config_001,
    #     name="hehe cpp_" + config_001.name,
    #     desc="C++ Sim of " + config_001.desc,
    #     SimulationEngineCls=CPPSimulationEngine,
    #     scenario_config=replace(
    #         config_001.scenario_config,
    #         AnnCls=CPPAnnouncement,
    #         override_announcements=tuple(
    #             [
    #                 CPPAnnouncement(
    #                     prefix_block_id=1,
    #                     prefix="1.2.0.0/16",
    #                     as_path=[
    #                         777,
    #                     ],
    #                     timestamp=0,
    #                     seed_asn=777,
    #                     roa_valid_length=True,
    #                     roa_origin=777,
    #                     recv_relationship=CPPRelationships.ORIGIN,
    #                 ),
    #                 CPPAnnouncement(
    #                     prefix_block_id=0,
    #                     prefix="1.2.3.0/24",
    #                     as_path=[
    #                         666,
    #                     ],
    #                     timestamp=1,
    #                     seed_asn=666,
    #                     roa_valid_length=False,
    #                     roa_origin=777,
    #                     recv_relationship=CPPRelationships.ORIGIN,
    #                 ),
    #             ]
    #         ),
    #     ),
    #     ASGraphAnalyzerCls=CPPASGraphAnalyzer,
    # )
    sim = EngineRunner(base_dir=Path(temp_dir.name), conf=erc)
    engine, outcomes_yaml, metric_tracker, scenario = sim.run_engine()

    response: FileResponse
    # Zip up system diagram, code snippet, engine and outcome yamls, and metric CSVs
    if download_zip:
        # Save engine run config in storage directory
        with open(f"{sim.storage_dir}/engine_config.pickle", "wb") as f:
            pickle.dump(erc, f)

        files_to_zip = [
            os.path.join(sim.storage_dir, file)
            for file in os.listdir(sim.storage_dir)
            if os.path.isfile(os.path.join(sim.storage_dir, file))
            and file != "guess.gv"
        ]
        files_to_zip.append("./api/examples/snippet.py")

        output_file = f"{sim.storage_dir}/output.zip"
        with ZipFile(output_file, "w") as zipf:
            for f in files_to_zip:
                zipf.write(f, os.path.basename(f))

        response = FileResponse(path=output_file, filename="output.zip")
    else:
        response = FileResponse(sim.diagram_path)

    # For some reason, I still get a CORS error if I do not include this line
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.post("/parse-config")
async def parse_config(config: Config):
    erc = config.to_engine_run_config()
    return "Good!"


if __name__ == "__main__":
    uvicorn.run(
        "server:app", host="localhost", port=8000, reload=True, log_level="debug"
    )
    temp_dir.cleanup()  # Delete temp dir when done
