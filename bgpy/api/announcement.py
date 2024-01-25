from pydantic import BaseModel
from typing import Optional


class Announcement(BaseModel):
    prefix_block_id: Optional[int] = None  # TODO: Hmm
    prefix: str
    as_path: list[int]
    timestamp: int
    seed_asn: Optional[int]
    roa_valid_length: Optional[bool]
    roa_origin: Optional[int]
    traceback_end: bool = True
