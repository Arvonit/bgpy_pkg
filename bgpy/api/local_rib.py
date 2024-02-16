from pydantic import BaseModel


class LocalRIB(BaseModel):
    type: str
    mask: str
    as_path: list[int]
