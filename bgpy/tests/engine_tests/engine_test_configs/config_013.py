from frozendict import frozendict
from bgpy.tests.engine_tests.as_graph_infos import as_graph_info_006
from bgpy.tests.engine_tests.utils import EngineTestConfig

from bgpy.simulation_engines.py_simulation_engine import (
    BGPSimplePolicy,
    ROVSimplePolicy,
)
from bgpy.enums import ASNs
from bgpy.simulation_frameworks.py_simulation_framework import (
    ScenarioConfig,
    NonRoutedSuperprefixHijack,
)


config_013 = EngineTestConfig(
    name="013",
    desc="NonRouted Superprefix Hijack",
    scenario_config=ScenarioConfig(
        ScenarioCls=NonRoutedSuperprefixHijack,
        AdoptPolicyCls=ROVSimplePolicy,
        BasePolicyCls=BGPSimplePolicy,
        override_attacker_asns=frozenset({ASNs.ATTACKER.value}),
        override_victim_asns=frozenset({ASNs.VICTIM.value}),
        override_non_default_asn_cls_dict=frozendict({2: ROVSimplePolicy}),
    ),
    as_graph_info=as_graph_info_006,
)
