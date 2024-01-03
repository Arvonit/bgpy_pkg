from typing import Optional, Type
from frozendict import frozendict
from pydantic import BaseModel, Field, conlist
from bgpy.as_graphs.base.as_graph_info import ASGraphInfo
from bgpy.as_graphs.base.links.customer_provider_link import CustomerProviderLink
from bgpy.as_graphs.base.links.peer_link import PeerLink
from bgpy.enums import ASNs, Relationships
from bgpy.simulation_engine.policies.bgp.bgp_simple_policy.bgp_simple_policy import (
    BGPSimplePolicy,
)
from bgpy.simulation_engine.policies.rov.rov_simple_policy import ROVSimplePolicy
from bgpy.simulation_framework.scenarios.hijack_scenarios.non_routed_prefix_hijack import (
    NonRoutedPrefixHijack,
)
from bgpy.simulation_framework.scenarios.hijack_scenarios.non_routed_superprefix_hijack import (
    NonRoutedSuperprefixHijack,
)
from bgpy.simulation_framework.scenarios.hijack_scenarios.non_routed_superprefix_prefix_hijack import (
    NonRoutedSuperprefixPrefixHijack,
)
from bgpy.simulation_framework.scenarios.hijack_scenarios.prefix_hijack import (
    PrefixHijack,
)
from bgpy.simulation_framework.scenarios.hijack_scenarios.subprefix_hijack import (
    SubprefixHijack,
)
from bgpy.simulation_framework.scenarios.hijack_scenarios.superprefix_prefix_hijack import (
    SuperprefixPrefixHijack,
)
from bgpy.simulation_framework.scenarios.scenario import Scenario
from bgpy.simulation_framework.scenarios.scenario_config import ScenarioConfig
from bgpy.simulation_framework.scenarios.valid_prefix import ValidPrefix
from bgpy.utils.engine_run_config import EngineRunConfig
from bgpy.simulation_engine.announcement import Announcement as BGPyAnnouncement


class CustomScenario(Scenario):
    """
    Class to allow API users to create their own scenario using their own
    defined scenarios.
    """

    def _get_announcements(self, *args, **kwargs):
        # Announcements will be populated from the scenario config's
        # override_announcements
        if len(self.scenario_config.override_announcements) == 0:
            raise ValueError("Scenario config must specify announcements")
        return ()


class Graph(BaseModel):
    # provider: cp_links[i][0], customer: cp_links[i][1]
    cp_links: list[conlist(int, min_length=2, max_length=2)]  # type: ignore
    peer_links: list[conlist(int, min_length=2, max_length=2)]  # type: ignore


class Announcement(BaseModel):
    prefix: str
    as_path: list[int]
    timestamp: int
    seed_asn: Optional[int]
    roa_valid_length: Optional[bool]
    roa_origin: Optional[int]
    recv_relationship: str
    traceback_end: bool = False


class Config(BaseModel):
    name: str
    desc: str
    scenario: Optional[str] = None
    # announcements: conlist(Announcement, max_length=10) = []  # type: ignore
    announcements: list[Announcement] = []
    attacker_asns: list[int] = []
    victim_asns: list[int] = []
    adopting_asns: dict[int, str] = {}
    propagation_rounds: int = Field(default=1, lt=3, gt=0)
    graph: Graph

    def get_as_graph(self) -> ASGraphInfo:
        return ASGraphInfo(
            customer_provider_links=frozenset(
                CustomerProviderLink(provider_asn=link[0], customer_asn=link[1])
                for link in self.graph.cp_links
            ),
            peer_links=frozenset(
                PeerLink(link[0], link[1]) for link in self.graph.peer_links
            ),
        )

    def _get_scenario_config(self) -> ScenarioConfig:
        scenario_class: Type[Scenario]
        match self.scenario:
            case "NonRoutedPrefixHijack":
                scenario_class = NonRoutedPrefixHijack
            case "NonRoutedSuperprefixHijack":
                scenario_class = NonRoutedSuperprefixHijack
            case "NonRoutedSuperprefixPrefixHijack":
                scenario_class = NonRoutedSuperprefixPrefixHijack
            case "PrefixHijack":
                scenario_class = PrefixHijack
            case "SubprefixHijack":
                scenario_class = SubprefixHijack
            case "SuperprefixPrefixHijack":
                scenario_class = SuperprefixPrefixHijack
            case _:  # Should match case when scenario is None
                scenario_class = CustomScenario

        adopting_asns: dict[int, type[BGPSimplePolicy]] = {}
        for asn, policy_str in self.adopting_asns.items():
            policy: type[BGPSimplePolicy]
            if policy_str == "ROV":
                policy = ROVSimplePolicy
            else:
                policy = BGPSimplePolicy
            adopting_asns[asn] = policy

        anns: list[BGPyAnnouncement] = []
        for a in self.announcements:
            # recv_relationship: Relationships
            recv_relationship = Relationships[a.recv_relationship.upper()]
            # match a.recv_relationship:
            #     case "providers":
            #         recv_relationship = Relationships.PROVIDERS
            #     case "peers":
            #         recv_relationship = Relationships.PEERS
            #     case "customers":
            #         recv_relationship = Relationships.CUSTOMERS
            #     case "origin":
            #         recv_relationship = Relationships.ORIGIN
            #     case _:
            #         recv_relationship = Relationships.UNKNOWN
            anns.append(
                BGPyAnnouncement(
                    prefix=a.prefix,
                    as_path=tuple(a.as_path),
                    timestamp=a.timestamp,
                    seed_asn=a.seed_asn,
                    roa_valid_length=a.roa_valid_length,
                    roa_origin=a.roa_origin,
                    recv_relationship=recv_relationship,
                    traceback_end=a.traceback_end,
                )
            )

        return ScenarioConfig(
            ScenarioCls=scenario_class,
            AdoptPolicyCls=ROVSimplePolicy,
            override_attacker_asns=frozenset(self.attacker_asns),
            override_victim_asns=frozenset(self.victim_asns),
            override_non_default_asn_cls_dict=frozendict(adopting_asns),
            override_announcements=tuple(anns),
        )

    def to_erc(self) -> EngineRunConfig:
        """
        Converts the JSON representation of a system configuration to a configuration that can
        be read by the engine runner.
        """

        return EngineRunConfig(
            name=self.name,
            desc=self.desc,
            scenario_config=self._get_scenario_config(),
            as_graph_info=self.get_as_graph(),
            propagation_rounds=self.propagation_rounds,
        )
