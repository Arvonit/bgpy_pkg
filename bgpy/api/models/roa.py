from pydantic import BaseModel
from typing import Optional

from bgpy.simulation_framework import ROAInfo


class APIROA(BaseModel):
    prefix: str
    origin: int
    max_length: Optional[int] = None

    def to_roa_info(self) -> ROAInfo:
        return ROAInfo(self.prefix, self.origin, self.max_length)  # type: ignore


class AnnouncementValidation(BaseModel):
    prefix: str
    origin: int
    roas: list[APIROA]
