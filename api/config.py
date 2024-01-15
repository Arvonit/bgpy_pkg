import ipaddress
from ipaddress import IPv4Network, IPv6Network
from typing import Optional, Type
from frozendict import frozendict
from pydantic import (
    BaseModel,
    Field,
    ValidationInfo,
    conlist,
    field_validator,
    model_validator,
)
from bgpy.as_graphs import ASGraphInfo, CustomerProviderLink, PeerLink
from bgpy.enums import PyRelationships, CPPRelationships  # type: ignore
from bgpy.simulation_engines.cpp_simulation_engine import (
    CPPSimulationEngine,
    CPPAnnouncement,  # type: ignore
)
from bgpy.simulation_frameworks.cpp_simulation_framework import CPPASGraphAnalyzer
from bgpy.simulation_engines.py_simulation_engine import (
    PyAnnouncement,
    PySimulationEngine,
)
from bgpy.simulation_engines.py_simulation_engine import (
    BGPSimplePolicy,
    ROVSimplePolicy,
)
from bgpy.simulation_frameworks.py_simulation_framework import (
    NonRoutedPrefixHijack,
    NonRoutedSuperprefixHijack,
    NonRoutedSuperprefixPrefixHijack,
    PrefixHijack,
    Scenario,
    ScenarioConfig,
    SubprefixHijack,
    SuperprefixPrefixHijack,
    ValidPrefix,
    PyASGraphAnalyzer,
)
from bgpy.utils import EngineRunConfig

USE_CPP_ENGINE = True
SUPPORTED_SCENARIOS_MAP = {
    NonRoutedPrefixHijack.__name__.lower(): NonRoutedPrefixHijack,
    NonRoutedSuperprefixHijack.__name__.lower(): NonRoutedSuperprefixHijack,
    NonRoutedSuperprefixPrefixHijack.__name__.lower(): NonRoutedSuperprefixPrefixHijack,
    PrefixHijack.__name__.lower(): PrefixHijack,
    SubprefixHijack.__name__.lower(): SubprefixHijack,
    SuperprefixPrefixHijack.__name__.lower(): SuperprefixPrefixHijack,
    ValidPrefix.__name__.lower(): ValidPrefix,
}


class CustomScenario(Scenario):
    """
    Allows API users to create their own scenario using self-defined announcements.
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
        """
        Converts the Graph JSON to an AS Graph object than can be used by the
        configuration for the EngineRunner.
        """
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
        # TODO: Need a more robust way of rejecting without counting all the nodes
        unique_nodes = set()
        for link in self.cp_links + self.peer_links:
            unique_nodes.update(link)
        size = len(unique_nodes)

        if size > 100_000:
            raise ValueError(f"Graph must have at most 100,000 ASes, not {size:,}")

        return self


class Announcement(BaseModel):
    prefix_block_id: int  # TODO: Hmm
    prefix: str
    as_path: list[int]
    timestamp: int
    seed_asn: Optional[int]
    roa_valid_length: Optional[bool]
    roa_origin: Optional[int]
    traceback_end: bool = True


class Config(BaseModel):
    name: str
    desc: str
    scenario: Optional[str] = None
    announcements: list[Announcement] = Field(default=[], validate_default=True)
    attacker_asns: list[int] = []
    victim_asns: list[int] = []
    asn_policy_map: dict[int, str] = {}
    propagation_rounds: int = Field(default=1, lt=3, gt=0)
    graph: Graph

    @field_validator("scenario")
    @classmethod
    def validate_scenario(cls, scenario: Optional[str]) -> Optional[str]:
        """
        Ensures the scenario is supported in BGPy.
        """
        if scenario is not None and scenario.lower() not in SUPPORTED_SCENARIOS_MAP:
            raise ValueError(f"{scenario} is not a supported scenario")

        return scenario

    @field_validator("announcements")
    @classmethod
    def validate_announcements(
        cls, announcements: list[Announcement], info: ValidationInfo
    ) -> list[Announcement]:
        # Ensure either scenario or announcement is specified
        if ("scenario" not in info.data or info.data["scenario"] is None) and len(
            announcements
        ) == 0:
            raise ValueError("Either a scenario or announcements must be specified")
        elif len(announcements) > 10:
            raise ValueError("The number of announcements exceeds the maximum of 10")

        # Ensure prefixes of all the announcements are valid and overlap
        prefixes: set[IPv4Network | IPv6Network] = set()
        for ann in announcements:
            curr_prefix = ipaddress.ip_network(ann.prefix)
            for existing_prefix in prefixes:
                if not existing_prefix.overlaps(curr_prefix):
                    raise ValueError(
                        f"Announcement with prefix {ann.prefix} does not overlap with "
                        "the rest of the announcements. Note this limitation only "
                        "exists for the API"
                    )
            prefixes.add(curr_prefix)

        return announcements

    @field_validator("asn_policy_map")
    @classmethod
    def validate_asn_policy_map(
        cls, asn_policy_map: dict[int, str], info: ValidationInfo
    ) -> dict[int, str]:
        """
        Ensures the policies given in the map are supported in BGPy (i.e., either ROV
        or BGP).
        """
        for _, policy_str in asn_policy_map.items():
            if policy_str.lower() not in ("rov", "bgp"):
                raise ValueError(
                    f"{policy_str} is not a valid AS policy. Please specify "
                    "either ROV or BGP"
                )
        return asn_policy_map

    def _get_scenario_config(self) -> ScenarioConfig:
        scenario_class: Type[Scenario]
        if self.scenario is not None:
            scenario_class = SUPPORTED_SCENARIOS_MAP[self.scenario.lower()]
        else:  # Announcements are given by user
            scenario_class = CustomScenario

        asn_policy_cls_map: dict[int, type[BGPSimplePolicy]] = {}
        for asn, policy_str in self.asn_policy_map.items():
            policy_cls: type[BGPSimplePolicy]
            # This is fine since we already validate against supported policies
            if policy_str.lower() == "rov":
                policy_cls = ROVSimplePolicy
            else:
                policy_cls = BGPSimplePolicy
            asn_policy_cls_map[asn] = policy_cls

        bgpy_announcements: list[PyAnnouncement | CPPAnnouncement] = []
        for announcement in self.announcements:
            bgpy_announcements.append(
                CPPAnnouncement(
                    **vars(announcement),
                    recv_relationship=CPPRelationships.ORIGIN,
                )
                if USE_CPP_ENGINE
                else PyAnnouncement(
                    **vars(announcement),
                    recv_relationship=PyRelationships.ORIGIN,
                )
            )

        return ScenarioConfig(
            ScenarioCls=scenario_class,
            AnnCls=CPPAnnouncement if USE_CPP_ENGINE else PyAnnouncement,
            AdoptPolicyCls=ROVSimplePolicy,
            override_attacker_asns=frozenset(self.attacker_asns),
            override_victim_asns=frozenset(self.victim_asns),
            override_non_default_asn_cls_dict=frozendict(asn_policy_cls_map),
            override_announcements=tuple(bgpy_announcements),
        )

    def to_engine_run_config(self) -> EngineRunConfig:
        """
        Converts the JSON representation of a system configuration to a configuration
        that can be read by the EngineRunner.
        """

        return EngineRunConfig(
            name=self.name,
            desc=self.desc,
            scenario_config=self._get_scenario_config(),
            as_graph_info=self.graph.to_as_graph(),
            propagation_rounds=self.propagation_rounds,
            SimulationEngineCls=CPPSimulationEngine
            if USE_CPP_ENGINE
            else PySimulationEngine,
            ASGraphAnalyzerCls=CPPASGraphAnalyzer
            if USE_CPP_ENGINE
            else PyASGraphAnalyzer,
        )

    @classmethod
    def from_engine_run_config(cls, engine_config: EngineRunConfig) -> "Config":
        return cls(
            name=engine_config.name,
            desc=engine_config.desc,
            scenario=None,
            announcements=engine_config.scenario_config.override_announcements,
            attacker_asns=list(engine_config.scenario_config.override_attacker_asns),
            victim_asns=list(engine_config.scenario_config.override_victim_asns),
            asn_policy_map=dict(
                engine_config.scenario_config.override_non_default_asn_cls_dict
            ),
            propagation_rounds=engine_config.propagation_rounds,
            graph=Graph.from_as_graph(engine_config.as_graph_info),
        )
