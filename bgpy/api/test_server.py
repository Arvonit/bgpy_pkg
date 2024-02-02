"""
Tests for BGPy API
"""

import pytest
from bgpy.enums import ASNs
from bgpy.simulation_engine.policies.bgp.bgp_simple_policy.bgp_simple_policy import (
    BGPSimplePolicy,
)
from bgpy.simulation_framework.scenarios.custom_scenarios.prefix_hijack import (
    PrefixHijack,
)
from bgpy.simulation_framework.scenarios.custom_scenarios.valid_prefix import (
    ValidPrefix,
)
from bgpy.simulation_framework.scenarios.scenario_config import ScenarioConfig
from bgpy.tests.engine_tests.as_graph_infos import as_graph_info_000

from bgpy.tests.engine_tests.engine_test_configs.examples import ex_config_000
from bgpy.utils.engine_run_config import EngineRunConfig
from frozendict import frozendict
from .config import Config
from .graph import Graph


def test_valid_config():
    config = Config(
        name="Valid Config",
        scenario="prefixhijack",
        graph=Graph(cp_links=[[1, 2], [2, 3]], peer_links=[[3, 4]]),
    )
    assert type(config) == Config


def test_invalid_scenario():
    with pytest.raises(ValueError, match="is not a supported scenario"):
        Config(
            name="Invalid Scenario Config",
            scenario="Foo",
            graph=Graph(cp_links=[[1, 2], [2, 3]], peer_links=[[3, 4]]),
        )


def test_invalid_asn_policies():
    with pytest.raises(ValueError):
        Config(
            name="Invalid ASN Policy Config",
            desc="ROV++ is not supported",
            scenario="PrefixHijack",
            graph=Graph(cp_links=[[1, 2]], peer_links=[[2, 3]]),
            asn_policy_map={1: "ROV++"},
        )


def test_no_scenario_or_announcements():
    with pytest.raises(ValueError):
        Config(
            name="Missing Scenario and Announcements",
            graph=Graph(cp_links=[[1, 2]], peer_links=[[2, 3]]),
        )


def test_engine_run_config_conversion():
    erc = EngineRunConfig(
        name="ex_000_valid_prefix_bgp_simple",
        desc="Valid prefix with BGP Simple",
        scenario_config=ScenarioConfig(
            ScenarioCls=ValidPrefix,
            BasePolicyCls=BGPSimplePolicy,
            override_attacker_asns=frozenset(),
            override_victim_asns=frozenset({ASNs.VICTIM.value}),
            override_non_default_asn_cls_dict=frozendict(),
        ),
        as_graph_info=as_graph_info_000,
    )
    assert erc == Config.from_engine_run_config(erc).to_engine_run_config()

    erc = EngineRunConfig(
        name="ex_001_prefix_hijack_bgp_simple",
        desc="Prefix hijack with BGP Simple",
        scenario_config=ScenarioConfig(
            ScenarioCls=PrefixHijack,
            BasePolicyCls=BGPSimplePolicy,
            override_attacker_asns=frozenset({ASNs.ATTACKER.value}),
            override_victim_asns=frozenset({ASNs.VICTIM.value}),
            override_non_default_asn_cls_dict=frozendict(),
        ),
        as_graph_info=as_graph_info_000,
    )
    assert erc == Config.from_engine_run_config(erc).to_engine_run_config()
