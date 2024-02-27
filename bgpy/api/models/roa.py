from pydantic import BaseModel

from bgpy.simulation_framework import ROAInfo


class APIROA(BaseModel):
    prefix: str
    origin: int

    def to_roa_info(self) -> ROAInfo:
        return ROAInfo(self.prefix, self.origin)
