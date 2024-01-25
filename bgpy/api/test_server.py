"""
Tests for BGPy API
"""

import pytest
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
    with pytest.raises(ValueError):
        Config(
            name="Invalid Scenario Config",
            scenario="Foo",
            graph=Graph(cp_links=[[1, 2], [2, 3]], peer_links=[[3, 4]]),
            propagation_rounds=2,
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
