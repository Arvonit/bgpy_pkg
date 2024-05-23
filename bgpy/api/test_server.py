"""
Tests for BGPy API
"""

import pytest
from bgpy.as_graphs import ASGraphInfo, PeerLink, CustomerProviderLink as CPLink
from bgpy.enums import ASNs
from bgpy.simulation_engine.policies.bgp.bgp.bgp import BGP
from bgpy.simulation_framework.scenarios.custom_scenarios.prefix_hijack import (
    PrefixHijack,
)
from bgpy.simulation_framework.scenarios.custom_scenarios.valid_prefix import (
    ValidPrefix,
)
from bgpy.simulation_framework.scenarios.scenario_config import ScenarioConfig
from bgpy.tests.engine_tests.engine_test_configs.examples.as_graph_info_000 import (
    as_graph_info_000,
)
from bgpy.utils.engine_run_config import EngineRunConfig
from frozendict import frozendict
from .models import APIConfig, APIGraph


def test_valid_config():
    config = APIConfig(
        name="Valid Config",
        scenario="PrefixHijack",
        attacker_asns=[666],
        victim_asns=[777],
        graph=APIGraph(cp_links=[[1, 2], [2, 3]], peer_links=[[3, 4]]),
    )
    assert type(config) == APIConfig


def test_invalid_scenario():
    with pytest.raises(ValueError, match="is not a supported scenario"):
        APIConfig(
            name="Invalid Scenario Config",
            scenario="ArvHijack",
            attacker_asns=[666],
            victim_asns=[777],
            graph=APIGraph(cp_links=[[1, 2], [2, 3]], peer_links=[[3, 4]]),
        )
        APIConfig(
            name="Invalid Scenario Config",
            scenario="CustomScenarios",  # typo
            attacker_asns=[666],
            victim_asns=[777],
            graph=APIGraph(cp_links=[[1, 2], [2, 3]], peer_links=[[3, 4]]),
        )


def test_invalid_asn_policies():
    with pytest.raises(ValueError, match="is not a supported AS policy"):
        APIConfig(
            name="Invalid ASN Policy Config",
            desc="ROV++ is not supported",
            scenario="PrefixHijack",
            attacker_asns=[666],
            victim_asns=[777],
            graph=APIGraph(cp_links=[[1, 2]], peer_links=[[2, 3]]),
            asn_policy_map={1: "ROV++"},
        )
        APIConfig(
            name="Invalid ASN Policy Config",
            desc="ASPA+Edge is not supported",
            scenario="PrefixHijack",
            attacker_asns=[666],
            victim_asns=[777],
            graph=APIGraph(cp_links=[[1, 2]], peer_links=[[2, 3]]),
            asn_policy_map={1: "ASPA", 2: "ASPA+Edge"},
        )


def test_no_scenario_or_announcements():
    with pytest.raises(
        ValueError, match="Either a scenario or announcements must be specified"
    ):
        APIConfig(
            name="Missing Scenario and Announcements",
            attacker_asns=[666],
            victim_asns=[777],
            graph=APIGraph(cp_links=[[1, 2]], peer_links=[[2, 3]]),
        )


def test_no_victim():
    with pytest.raises(
        ValueError,
        match="There must be one AS with a role of victim",
    ):
        APIConfig(
            name="No Victim",
            scenario="SubprefixHijack",
            attacker_asns=[666],
            graph=APIGraph(cp_links=[[1, 2]], peer_links=[[2, 3]]),
        )
        APIConfig(
            name="No Victim",
            scenario="SubprefixHijack",
            attacker_asns=[666],
            victim_asns=[777, 778],
            graph=APIGraph(cp_links=[[1, 2]], peer_links=[[2, 3]]),
        )


def test_no_attacker():
    with pytest.raises(
        ValueError,
        match="Graph must have at least one attacker",
    ):
        APIConfig(
            name="No Victim",
            scenario="SubprefixHijack",
            victim_asns=[777],
            graph=APIGraph(cp_links=[[1, 2]], peer_links=[[2, 3]]),
        )

    config = APIConfig(
        name="No Victim",
        scenario="ValidPrefix",
        victim_asns=[777],
        graph=APIGraph(cp_links=[[1, 2]], peer_links=[[2, 3]]),
    )
    assert type(config) == APIConfig


def test_engine_run_config_conversion():
    as_graph = ASGraphInfo(
        peer_links=frozenset(
            {
                PeerLink(8, 9),
                PeerLink(9, 10),
                PeerLink(9, 3),
            }
        ),
        customer_provider_links=frozenset(
            [
                CPLink(provider_asn=1, customer_asn=ASNs.ATTACKER.value),
                CPLink(provider_asn=2, customer_asn=ASNs.ATTACKER.value),
                CPLink(provider_asn=2, customer_asn=ASNs.VICTIM.value),
                CPLink(provider_asn=4, customer_asn=ASNs.VICTIM.value),
                CPLink(provider_asn=5, customer_asn=1),
                # CPLink(provider_asn=5, customer_asn=2),
                CPLink(provider_asn=8, customer_asn=1),
                CPLink(provider_asn=8, customer_asn=2),
                CPLink(provider_asn=9, customer_asn=4),
                CPLink(provider_asn=10, customer_asn=ASNs.VICTIM.value),
                CPLink(provider_asn=11, customer_asn=8),
                CPLink(provider_asn=11, customer_asn=9),
                CPLink(provider_asn=11, customer_asn=10),
                CPLink(provider_asn=12, customer_asn=10),
            ]
        ),
    )

    erc = EngineRunConfig(
        name="Valid Prefix",
        desc="Valid prefix with BGP",
        scenario_config=ScenarioConfig(
            ScenarioCls=ValidPrefix,
            override_attacker_asns=frozenset({}),
            override_victim_asns=frozenset({ASNs.VICTIM.value}),
            override_non_default_asn_cls_dict=frozendict(),
            num_attackers=0,
        ),
        as_graph_info=as_graph,
    )
    assert erc == APIConfig.from_engine_run_config(erc).to_engine_run_config()

    erc = EngineRunConfig(
        name="Prefix Hijack",
        desc="Prefix hijack with BGP",
        scenario_config=ScenarioConfig(
            ScenarioCls=PrefixHijack,
            override_attacker_asns=frozenset({ASNs.ATTACKER.value}),
            override_victim_asns=frozenset({ASNs.VICTIM.value}),
            override_non_default_asn_cls_dict=frozendict(),
        ),
        as_graph_info=as_graph,
    )
    assert erc == APIConfig.from_engine_run_config(erc).to_engine_run_config()
