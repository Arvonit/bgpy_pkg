from typing import Optional

from pydantic import BaseModel

from bgpy.enums import Relationships
from bgpy.simulation_engine import Announcement as BGPyAnnouncement


class APIAnnouncement(BaseModel):
    prefix: str
    as_path: list[int]
    seed_asn: Optional[int]
