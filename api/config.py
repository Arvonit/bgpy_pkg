from ipaddress import IPv4Network
from typing import Optional, Type, Annotated
from frozendict import frozendict
from pydantic import (
    BaseModel,
    Field,
    ValidationInfo,
    conlist,
    field_validator,
    model_validator,
)
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


SUPPORTED_SCENARIOS_MAP = {
    "nonroutedprefixhijack": NonRoutedPrefixHijack,
    "nonroutedsuperprefixhijack": NonRoutedSuperprefixHijack,
    "nonroutedsuperprefixprefixhijack": NonRoutedSuperprefixPrefixHijack,
    "prefixhijack": PrefixHijack,
    "subprefixhijack": SubprefixHijack,
    "superprefixprefixhijack": SuperprefixPrefixHijack,
}


class CustomScenario(Scenario):
    """
    Class to allow API users to create their own scenario using self-defined
    announcements.
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

    def to_as_graph(self) -> ASGraphInfo:
        return ASGraphInfo(
            customer_provider_links=frozenset(
                CustomerProviderLink(provider_asn=link[0], customer_asn=link[1])
                for link in self.cp_links
            ),
            peer_links=frozenset(
                PeerLink(link[0], link[1]) for link in self.peer_links
            ),
        )

    @model_validator(mode="after")
    def check_graph_size(self, info: ValidationInfo) -> "Graph":
        """
        Ensures the graph has at most 100,000 ASes.
        """
        size = len(self.to_as_graph().asns)
        # print(size)
        if size > 100_000:
            raise ValueError(f"Graph must have at most 100,000 ASes, not {size:,}")

        return self


class Announcement(BaseModel):
    prefix: str
    as_path: list[int]
    timestamp: int
    seed_asn: Optional[int]
    roa_valid_length: Optional[bool]
    roa_origin: Optional[int]
    # recv_relationship: str
    traceback_end: bool = True


class Config(BaseModel):
    name: str
    desc: str
    scenario: Optional[str] = None
    announcements: list[Announcement] = Field(default=[], validate_default=True)
    attacker_asns: list[int] = []
    victim_asns: list[int] = []
    adopting_asns: dict[int, str] = {}
    propagation_rounds: int = Field(default=1, lt=3, gt=0)
    graph: Graph

    @field_validator("scenario")
    @classmethod
    def validate_scenario(cls, v: Optional[str], info: ValidationInfo) -> Optional[str]:
        if v is not None and v.lower() not in SUPPORTED_SCENARIOS_MAP:
            raise ValueError(f"{v} is not a supported scenario")

        return v

    @field_validator("announcements")
    @classmethod
    def validate_announcements(
        cls, v: list[Announcement], info: ValidationInfo
    ) -> list[Announcement]:
        # Ensure either scenario or announcement is specified, but not both
        if "scenario" in info.data and info.data["scenario"]:
            if len(v) > 0:
                raise ValueError("Either specify a scenario or announcements, not both")
        elif len(v) == 0:
            raise ValueError("Either a scenario or announcements must be specified")
        elif len(v) > 10:
            raise ValueError(
                "The number of announcements has exceeded the maximum of 10"
            )

        # Ensure prefixes of all the announcements are valid and overlap
        print("validating")
        print(info.data)
        prefixes: set[IPv4Network] = set()
        for ann in v:
            curr_prefix = IPv4Network(ann.prefix)
            for existing_prefix in prefixes:
                if not existing_prefix.overlaps(curr_prefix):
                    raise ValueError(
                        f"Announcement with prefix {ann.prefix} does not overlap with "
                        "the rest of the announcements"
                    )
            prefixes.add(curr_prefix)
        print("good")

        return v

    def get_scenario_config(self) -> ScenarioConfig:
        scenario_class: Type[Scenario]
        if self.scenario is not None:
            scenario_class = SUPPORTED_SCENARIOS_MAP[self.scenario.lower()]
        else:  # Announcements are given by user
            scenario_class = CustomScenario

        adopting_asns: dict[int, type[BGPSimplePolicy]] = {}
        for asn, policy_str in self.adopting_asns.items():
            policy: type[BGPSimplePolicy]
            if policy_str.lower() == "rov":
                policy = ROVSimplePolicy
            else:
                policy = BGPSimplePolicy
            adopting_asns[asn] = policy

        anns: list[BGPyAnnouncement] = []
        for a in self.announcements:
            # recv_relationship = Relationships[a.recv_relationship.upper()]
            anns.append(
                BGPyAnnouncement(
                    prefix=a.prefix,
                    as_path=tuple(a.as_path),
                    timestamp=a.timestamp,
                    seed_asn=a.seed_asn,
                    roa_valid_length=a.roa_valid_length,
                    roa_origin=a.roa_origin,
                    recv_relationship=Relationships.ORIGIN,
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
        Converts the JSON representation of a system configuration to a configuration
        that can be read by the engine runner.
        """

        return EngineRunConfig(
            name=self.name,
            desc=self.desc,
            scenario_config=self.get_scenario_config(),
            as_graph_info=self.graph.to_as_graph(),
            propagation_rounds=self.propagation_rounds,
        )
