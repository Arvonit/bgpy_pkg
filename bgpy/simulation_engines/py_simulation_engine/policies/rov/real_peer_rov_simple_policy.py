from typing import TYPE_CHECKING

from bgpy.simulation_engines.py_simulation_engine.policies.bgp import BGPSimplePolicy
from bgpy.enums import PyRelationships


if TYPE_CHECKING:
    from bgpy.simulation_engines.cpp_simulation_engine.cpp_announcement import (
        CPPAnnouncement as CPPAnn,
    )

    from bgpy.simulation_engines.py_simulation_engine.py_announcement import (
        PyAnnouncement as PyAnn,
    )



class RealPeerROVSimplePolicy(BGPSimplePolicy):
    """An Policy that deploys ROV in real life, but only filters peers"""

    name: str = "RealPeerROVSimple"

    # mypy doesn't understand that this func is valid
    def _valid_ann(self, ann: PyAnn | CPPAnn, *args, **kwargs) -> bool:  # type: ignore
        """Returns announcement validity

        Returns false if invalid by roa,
        otherwise uses standard BGP (such as no loops, etc)
        to determine validity

        Note that since this is real world ROV for peers, it only filters anns coming
        from peers
        """

        # Invalid by ROA is not valid by ROV
        # Since this type of real world ROV only does peer filtering, only peers here
        if ann.invalid_by_roa and ann.recv_relationship.value == PyRelationships.PEERS.value:
            return False
        # Use standard BGP to determine if the announcement is valid
        else:
            # Mypy doesn't map superclasses properly
            return super(RealPeerROVSimplePolicy, self)._valid_ann(  # type: ignore
                ann, *args, **kwargs
            )
