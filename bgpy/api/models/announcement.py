from typing import Optional

from pydantic import BaseModel

from bgpy.enums import Relationships
from bgpy.simulation_engine import Announcement as BGPyAnnouncement


class APIAnnouncement(BaseModel):
    prefix: str
    as_path: list[int]
    # timestamp: int
    seed_asn: Optional[int]
    # roa_valid_length: Optional[bool]
    # roa_origin: Optional[int]
    # traceback_end: bool = True

    # def to_bgpy_announcement(self) -> BGPyAnnouncement:
    #     return BGPyAnnouncement(
    #         **vars(self),
    #         recv_relationship=Relationships.ORIGIN,
    #     )
