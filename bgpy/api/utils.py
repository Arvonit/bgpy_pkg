import ipaddress
from .models import LocalRIB
from bgpy.simulation_engine import SimulationEngine
from bgpy.simulation_framework import Scenario


# TODO: LocalRIB is "not JSON serializable"
def get_local_ribs(
    engine: SimulationEngine, scenario: Scenario
) -> dict[int, list[LocalRIB]]:
    """
    Retrieves the Local RIB for all ASNs in a simulation.
    """

    local_rib_dict = {}

    for as_obj in engine.as_graph:
        local_rib_anns = tuple(list(as_obj.policy._local_rib.values()))
        local_rib_anns = tuple(
            sorted(
                local_rib_anns,
                key=lambda x: ipaddress.ip_network(x.prefix).num_addresses,
                reverse=True,
            )
        )

        rib_entries = []
        for ann in local_rib_anns:
            mask = "/" + ann.prefix.split("/")[-1]
            as_path = list(ann.as_path)
            type = None
            if any(x in ann.as_path for x in scenario.attacker_asns):
                type = "attacker"
            elif any(x == ann.origin for x in scenario.victim_asns):
                type = "victim"
            if type is not None:
                rib_entry = {"type": type, "mask": mask, "as_path": as_path}
                # rib_entry = LocalRIB(type=type, mask=mask, as_path=as_path)
                rib_entries.append(rib_entry)

        local_rib_dict[as_obj.asn] = rib_entries

    return local_rib_dict
