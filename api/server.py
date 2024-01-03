from pathlib import Path
from typing import Any, Sequence
from fastapi import FastAPI, HTTPException, Request
from fastapi import status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import ValidationError
import yaml
from bgpy.tests.engine_tests.engine_test_configs import config_001
from bgpy.utils.engine_runner import EngineRunner
from config import Config
import uvicorn


app = FastAPI()
origins = [
    "http://localhost:5173",
    "localhost:5173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/simulate")
async def simulate(config: Config):
    # Ensure there are less than 100,000 ASes in the graph
    if len(config.get_as_graph().asns) >= 100_000:
        raise HTTPException(
            status_code=422,
            detail=[{"msg": "Graph should have less than 100,000 ASes"}],
        )
    # print(config.to_erc())

    sim = EngineRunner(base_dir=Path("/tmp/api"), conf=config.to_erc())
    engine, outcomes_yaml, metric_tracker, scenario = sim.run_engine()
    response = FileResponse(sim.diagram_path)
    # For some reason, I still get a CORS error if I do not include this line
    response.headers["Access-Control-Allow-Origin"] = "*"
    # print(outcomes_yaml)
    print("success!")
    return response


@app.post("/parse-config")
async def parse_config(config: Config):
    erc = config.to_erc()
    print(yaml.dump(erc))
    return "Hello, world!"


if __name__ == "__main__":
    uvicorn.run(
        "server:app", host="localhost", port=8000, reload=True, log_level="debug"
    )
