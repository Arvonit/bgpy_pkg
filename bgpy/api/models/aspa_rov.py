"""
Combines ASPA with ROV
"""

from bgpy.simulation_engine import ASPA, ROV, Announcement
from bgpy.enums import Relationships


class ASPAROV(ASPA, ROV):
    """
    A policy that deploys ASPA as well as ROV. This is more likely to occur in the real
    world.
    """

    name: str = "ASPA+ROV"

    def _valid_ann(self, ann: Announcement, from_rel: Relationships) -> bool:
        return ROV._valid_ann(self, ann, from_rel) and ASPA._valid_ann(
            self, ann, from_rel
        )
