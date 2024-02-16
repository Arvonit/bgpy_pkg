import os
import pickle
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from tempfile import TemporaryDirectory
from pydantic import ValidationError
from zipfile import ZipFile
from bgpy.utils import EngineRunner
from .models import APIConfig
from .utils import get_local_ribs


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Delete temp_dir on shutdown
    yield
    temp_dir.cleanup()


temp_dir = TemporaryDirectory()
app = FastAPI(docs_url="/api/docs", openapi_url="/api/openapi.json", lifespan=lifespan)


@app.post("/api/simulate")
async def simulate(
    config: APIConfig, include_diagram: bool = False, download_zip: bool = False
):
    # TODO: Check JSON file size to ensure graph isn't too big
    # https://github.com/tiangolo/fastapi/issues/362

    print(config)
    base_dir = Path(temp_dir.name) / uuid.uuid4().hex
    erc = config.to_engine_run_config()
    sim = EngineRunner(base_dir=base_dir, conf=erc)
    engine, outcomes_yaml, metric_tracker, scenario = sim.run_engine()

    response: FileResponse | JSONResponse
    # Zip up system diagram, code snippet, engine and outcome yamls, and metric CSVs
    if download_zip:
        # Save engine run config in storage directory
        with open(f"{sim.storage_dir}/engine_config.pickle", "wb") as f:
            pickle.dump(erc, f)

        cwd = Path(__file__).parent
        files_to_zip = [
            os.path.join(sim.storage_dir, file)
            for file in os.listdir(sim.storage_dir)
            if os.path.isfile(os.path.join(sim.storage_dir, file))
            and file != "guess.gv"
        ]
        files_to_zip.append(f"{str(cwd)}/examples/snippet.py")

        output_file = f"{sim.storage_dir}/output.zip"
        with ZipFile(output_file, "w") as zipf:
            for f in files_to_zip:
                zipf.write(f, os.path.basename(f))

        response = FileResponse(path=output_file, filename="output.zip")
    elif include_diagram:
        response = FileResponse(sim.diagram_path)
        # response = FileResponse(sim.storage_dir / "guess.gv")
    else:
        # TODO: Make type for this
        result = {
            "outcome": outcomes_yaml,
            "local_ribs": get_local_ribs(engine, scenario),
        }
        response = JSONResponse(content=result)

    return response


@app.get("/api/examples")
async def get_examples():
    return []
