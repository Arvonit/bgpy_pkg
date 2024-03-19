import ipaddress
import os
import pickle
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from tempfile import TemporaryDirectory
from zipfile import ZipFile
from roa_checker import ROAChecker, ROAValidity
from bgpy.utils import EngineRunner
from .models import APIConfig, APIROA, AnnouncementValidation
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
    else:
        # TODO: Make type for this
        result = {
            "outcome": outcomes_yaml,
            "local_ribs": get_local_ribs(engine, scenario),
        }
        response = JSONResponse(content=result)

    return response


@app.post("/api/validate-roa")
async def validate_roa(validation: AnnouncementValidation):
    roa_infos = [roa.to_roa_info() for roa in validation.roas]
    checker = ROAChecker()

    # Add ROAs to trie
    for roa in roa_infos:
        checker.insert(ipaddress.ip_network(roa.prefix), roa.origin, roa.max_length)

    # Get validity
    validity, _ = checker.get_validity(
        ipaddress.ip_network(validation.prefix), validation.origin
    )
    print(validation.prefix, validation.origin, str(validity))
    print(validation.roas)

    if ROAValidity.is_valid(validity):
        return "Valid"
    elif ROAValidity.is_invalid(validity):
        return "Invalid"
    else:
        return "Unknown"
