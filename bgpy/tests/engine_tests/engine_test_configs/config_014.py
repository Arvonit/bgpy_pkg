from frozendict import frozendict
from bgpy.tests.engine_tests.graphs import graph_006
from bgpy.tests.engine_tests.utils import EngineTestConfig

from bgpy.simulation_engine import BGPSimplePolicy, ROVPolicy
from bgpy.enums import ASNs
from bgpy.simulation_framework import (
    ScenarioConfig,
    NonRoutedSuperprefixHijack,
)


config_014 = EngineTestConfig(
    name="014",
    desc="NonRouted Superprefix Hijack",
    scenario_config=ScenarioConfig(
        ScenarioCls=NonRoutedSuperprefixHijack,
        AdoptPolicyCls=ROVPolicy,
        BasePolicyCls=BGPSimplePolicy,
        override_attacker_asns=frozenset({ASNs.ATTACKER.value}),
        override_victim_asns=frozenset({ASNs.VICTIM.value}),
        override_non_default_asn_cls_dict=frozendict({2: ROVPolicy}),
    ),
    graph=graph_006,
)
