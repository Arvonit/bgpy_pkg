import ipaddress
from ipaddress import IPv4Network, IPv6Network
from typing import Optional, Type

from frozendict import frozendict
from pydantic import BaseModel, Field, ValidationInfo, field_validator

from bgpy.api.models.aspa_rov import ASPAROV
from bgpy.enums import Relationships
from bgpy.simulation_engine import Announcement as BGPyAnnouncement
from bgpy.simulation_engine import (
    ASPA,
    BGPSec,
    BGP,
    OnlyToCustomers,
    PathEnd,
    Policy,
    ROV,
)
from bgpy.simulation_framework import (
    AccidentalRouteLeak,
    NonRoutedPrefixHijack,
    NonRoutedSuperprefixHijack,
    NonRoutedSuperprefixPrefixHijack,
    PrefixHijack,
    Scenario,
    ScenarioConfig,
    SubprefixHijack,
    SuperprefixPrefixHijack,
    ValidPrefix,
    ROAInfo,
)
from bgpy.simulation_framework.scenarios.preprocess_anns_funcs import (
    PREPROCESS_ANNS_FUNC_TYPE,
    noop,
    origin_hijack,
    shortest_path_export_all_hijack,
)
from bgpy.simulation_framework.scenarios.scenario_config import MISSINGPolicy
from bgpy.utils import EngineRunConfig

from .announcement import APIAnnouncement
from .graph import APIGraph
from .roa import APIROA
from .custom_scenario import CustomScenario

SUPPORTED_SCENARIOS_MAP = {
    CustomScenario.__name__.lower(): CustomScenario,
    SubprefixHijack.__name__.lower(): SubprefixHijack,
    PrefixHijack.__name__.lower(): PrefixHijack,
    ValidPrefix.__name__.lower(): ValidPrefix,
    NonRoutedPrefixHijack.__name__.lower(): NonRoutedPrefixHijack,
    NonRoutedSuperprefixHijack.__name__.lower(): NonRoutedSuperprefixHijack,
    NonRoutedSuperprefixPrefixHijack.__name__.lower(): NonRoutedSuperprefixPrefixHijack,
    SuperprefixPrefixHijack.__name__.lower(): SuperprefixPrefixHijack,
    AccidentalRouteLeak.__name__.lower(): AccidentalRouteLeak,
}
SUPPORTED_POLICIES_MAP = {
    "bgp": BGP,
    "rov": ROV,
    "aspa": ASPA,
    "aspa+rov": ASPAROV,
    "bgpsec": BGPSec,
    "otc": OnlyToCustomers,
    "path-end": PathEnd,
}
SUPPORTED_SCENARIO_MODIFIERS = {
    origin_hijack.__name__.lower(): origin_hijack,
    shortest_path_export_all_hijack.__name__.lower(): shortest_path_export_all_hijack,
    noop.__name__.lower(): noop,
}


class APIConfig(BaseModel):
    """
    A model representing the configuration of a simulation on the BGPy website.
    """

    name: str = ""
    desc: str = ""
    scenario: Optional[str] = None  # TODO: Move to str
    scenario_modifier: Optional[str] = None  # TODO: Remove
    announcements: list[APIAnnouncement] = Field(default=[], validate_default=True)
    roas: list[APIROA] = []
    attacker_asns: list[int] = Field(default=[], validate_default=True)
    victim_asns: list[int] = Field(default=[], validate_default=True)
    asn_policy_map: dict[int, str] = {}
    graph: APIGraph

    @field_validator("scenario")
    @classmethod
    def validate_scenario(cls, scenario: Optional[str]) -> Optional[str]:
        """
        Ensures the scenario is supported by BGPy.
        """
        if scenario is not None and scenario.lower() not in SUPPORTED_SCENARIOS_MAP:
            raise ValueError(f"{scenario} is not a supported scenario")

        return scenario

    @field_validator("scenario_modifier")
    @classmethod
    def validate_scenario_modifier(
        cls, scenario_modifier: Optional[str], info: ValidationInfo
    ) -> Optional[str]:
        """
        Ensures the scenario modifier is supported by BGPy and is not used with a
        custom scenario.
        """
        if scenario_modifier is not None and (
            "scenario" not in info.data
            or info.data["scenario"] is None
            or info.data["scenario"] == "customscenario"
        ):
            raise ValueError(f"Cannot use attack modifier for custom scenario")
        if (
            scenario_modifier is not None
            and scenario_modifier.lower() not in SUPPORTED_SCENARIO_MODIFIERS
        ):
            raise ValueError(f"{scenario_modifier} is not a support attack modifier")
        return scenario_modifier

    @field_validator("announcements")
    @classmethod
    def validate_announcements(
        cls, announcements: list[APIAnnouncement], info: ValidationInfo
    ) -> list[APIAnnouncement]:
        """ """
        # Ensure either scenario or announcement is specified
        if (
            "scenario" not in info.data
            or info.data["scenario"] is None
            or info.data["scenario"] == "customscenario"
        ) and len(announcements) == 0:
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
                        "exists for the website"
                    )
            prefixes.add(curr_prefix)

        return announcements

    @field_validator("attacker_asns")
    @classmethod
    def validate_attacker_asns(
        cls, attacker_asns: list[int], info: ValidationInfo
    ) -> list[int]:
        if (
            "scenario" not in info.data
            or info.data["scenario"] is None
            or info.data["scenario"] == "customscenario"
        ):
            return attacker_asns
        elif (
            info.data["scenario"].lower() != ValidPrefix.__name__.lower()
            and len(attacker_asns) < 1
        ):
            raise ValueError("Graph must have at least one attacker")

        return attacker_asns

    @field_validator("victim_asns")
    @classmethod
    def validate_victim_asns(cls, victim_asns: list[int]) -> list[int]:
        if len(victim_asns) != 1:
            raise ValueError(
                "There must be one AS with a role of victim " "(the legitimate origin)"
            )

        return victim_asns

    @field_validator("asn_policy_map")
    @classmethod
    def validate_asn_policy_map(
        cls, asn_policy_map: dict[int, str], info: ValidationInfo
    ) -> dict[int, str]:
        """
        Ensures the policies given in the map are supported in BGPy (i.e., either ROV
        or BGP).
        """
        # Error if multiple policies are used in SPEA
        if (
            "scenario_modifier" in info.data
            and info.data["scenario_modifier"]
            == shortest_path_export_all_hijack.__name__.lower()
            and len(set(asn_policy_map.values())) > 1
        ):
            raise ValueError(
                "Multiple policies cannot be used with the Shortest Path Export "
                "All hijack"
            )

        for _, policy_str in asn_policy_map.items():
            if (
                policy_str is not None
                and policy_str.lower() not in SUPPORTED_POLICIES_MAP
            ):
                raise ValueError(f"{policy_str} is not a supported AS policy")
        return asn_policy_map

    def _get_scenario_config(self) -> ScenarioConfig:
        scenario_class: Type[Scenario]
        if self.scenario is not None:
            scenario_class = SUPPORTED_SCENARIOS_MAP[self.scenario.lower()]
        else:  # Announcements are given by user
            scenario_class = CustomScenario

        preprocess_func: PREPROCESS_ANNS_FUNC_TYPE
        if self.scenario_modifier is not None:
            preprocess_func = SUPPORTED_SCENARIO_MODIFIERS[
                self.scenario_modifier.lower()
            ]
        else:
            preprocess_func = noop

        # Get first policy in map for adopt policy (used in SPEA)
        adopt_policy_class: type[Policy]
        first_policy = next(iter(self.asn_policy_map.values()), None)
        if first_policy is not None:
            adopt_policy_class = SUPPORTED_POLICIES_MAP[first_policy.lower()]
        else:
            adopt_policy_class = MISSINGPolicy

        asn_policy_class_map: dict[int, type[BGP]] = {}
        for asn, policy_str in self.asn_policy_map.items():
            policy_cls: type[BGP]
            if policy_str is not None:
                policy_cls = SUPPORTED_POLICIES_MAP[policy_str.lower()]
            else:
                policy_cls = BGP
            asn_policy_class_map[asn] = policy_cls

        bgpy_announcements: list[BGPyAnnouncement] = []
        for ann in self.announcements:
            ann.as_path = tuple(ann.as_path)  # type: ignore
            bgpy_announcements.append(
                BGPyAnnouncement(
                    **vars(ann),
                    next_hop_asn=ann.seed_asn,
                    timestamp=(
                        0 if ann.seed_asn in self.victim_asns else 1
                    ),  # TODO: Refactor
                    recv_relationship=Relationships.ORIGIN,
                )
            )

        roa_infos: list[ROAInfo] = []
        for roa in self.roas:
            roa_infos.append(roa.to_roa_info())
        # print(bgpy_announcements)

        return ScenarioConfig(
            ScenarioCls=scenario_class,
            propagation_rounds=scenario_class.min_propagation_rounds,
            # BasePolicyCls=base_policy_class,
            AdoptPolicyCls=adopt_policy_class,
            num_attackers=len(self.attacker_asns),
            num_victims=len(self.victim_asns),
            preprocess_anns_func=preprocess_func,
            override_attacker_asns=frozenset(self.attacker_asns),
            override_victim_asns=frozenset(self.victim_asns),
            override_non_default_asn_cls_dict=frozendict(asn_policy_class_map),
            override_announcements=tuple(bgpy_announcements),
            override_roa_infos=tuple(roa_infos),
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
        )

    @classmethod
    def from_engine_run_config(cls, engine_config: EngineRunConfig) -> "APIConfig":
        cp_links = [
            [link.provider_asn, link.customer_asn]
            for link in engine_config.as_graph_info.customer_provider_links
        ]
        peer_links = [
            [link.peer_asns[0], link.peer_asns[1]]
            for link in engine_config.as_graph_info.peer_links
        ]
        propagation_ranks = [
            list(asns) for asns in engine_config.as_graph_info.diagram_ranks
        ]
        scenario = (
            engine_config.scenario_config.ScenarioCls.__name__
            if engine_config.scenario_config.ScenarioCls
            else None
        )
        scenario_modifier = (
            engine_config.scenario_config.preprocess_anns_func.__name__
            if engine_config.scenario_config.preprocess_anns_func != noop
            else None
        )
        base_policy = (
            engine_config.scenario_config.BasePolicyCls.__name__
            if "BGP" not in engine_config.scenario_config.BasePolicyCls.__name__
            else None
        )
        adopt_policy = (
            engine_config.scenario_config.AdoptPolicyCls.__name__
            if "MISSING" not in engine_config.scenario_config.AdoptPolicyCls.__name__
            else None
        )
        attacker_asns = list(engine_config.scenario_config.override_attacker_asns or [])
        victim_asns = list(engine_config.scenario_config.override_victim_asns or [])
        asn_policy_map = {}
        for (
            asn,
            policy_cls,
        ) in engine_config.scenario_config.override_non_default_asn_cls_dict.items():
            asn_policy_map[asn] = policy_cls.name.lower()

        return cls(
            name=engine_config.name,
            desc=engine_config.desc,
            scenario=scenario,
            scenario_modifier=scenario_modifier,
            # base_policy=base_policy,
            # adopt_policy=adopt_policy,
            announcements=[],  # TODO: Assuming no data available for announcements in EngineRunConfig
            attacker_asns=attacker_asns,
            victim_asns=victim_asns,
            asn_policy_map=asn_policy_map,
            # propagation_rounds=engine_config.scenario_config.propagation_rounds,
            graph=APIGraph(
                cp_links=cp_links,
                peer_links=peer_links,
                # propagation_ranks=propagation_ranks,
            ),
        )
