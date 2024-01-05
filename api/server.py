import os
import uvicorn
import pickle
import tempfile
from pathlib import Path
from typing import Any, Sequence
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
    sim = EngineRunner(base_dir=Path(temp_dir.name), conf=erc)
    engine, outcomes_yaml, metric_tracker, scenario = sim.run_engine()

    response: FileResponse
    # Zip up system diagram, code snippet, engine and outcome yamls, and metric CSVs
    if download_zip:
        # Save engine run config in storage directory
        with open(f"{sim.storage_dir}/engine_config.pickle", "wb") as f:
            # TODO: Switch to saving the config as a YAML
            # I am using pickle for now because I was having trouble deserializing the
            # ScenarioConfig using YAML. I need to come back to this soon since
            # pickle is not ideal (allows arbitrary code execution and not
            # human-readable).
            pickle.dump(erc, f)

        files_to_zip = [
            os.path.join(sim.storage_dir, file)
            for file in os.listdir(sim.storage_dir)
            if os.path.isfile(os.path.join(sim.storage_dir, file))
            and file != "guess.gv"
        ]
        files_to_zip.append("./examples/snippet.py")

        # TODO: Save zip in temp dir
        output_file = "output.zip"
        with ZipFile(output_file, "w") as zipf:
            for f in files_to_zip:
                zipf.write(f, os.path.basename(f))

        response = FileResponse(path=output_file, filename=output_file)
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
