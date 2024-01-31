from frozendict import frozendict
from bgpy.enums import ASNs
from .as_graph_info_000 import as_graph_info_000
from bgpy.tests.engine_tests.utils import EngineTestConfig

from bgpy.simulation_engine import (
    BGPSimplePolicy,
)
from bgpy.simulation_framework import (
    ScenarioConfig,
    SubprefixHijack,
)


desc = (
    "Subprefix hijack with BGP Simple"
    "Valley Free (Gao Rexford) Demonstration\n"
    "import policy\n"
    "AS 9, prefix, shows customer > peer\n"
    "AS 9, subprefix, shows peer > provider\n"
    "AS 11, prefix, shows shortest AS path\n"
    "AS 5 and AS 8, subprefix, tiebreaker by lowest ASN\n"
    "export policy\n"
    "AS 10, subprefix, shows anns from providers only export to customers\n"
    "AS 9, subprefix, shows anns from peers only export to customers\n"
    "(All ASes show exporting to cusotmers)\n"
    "hidden hijack\n"
    "AS 12 shows a hidden hijack\n"
)

ex_config_002 = EngineTestConfig(
    name="ex_002_subprefix_hijack_bgp_simple_gao_rexford_demo",
    desc=desc,
    scenario_config=ScenarioConfig(
        ScenarioCls=SubprefixHijack,
        BasePolicyCls=BGPSimplePolicy,
        override_attacker_asns=frozenset({ASNs.ATTACKER.value}),
        override_victim_asns=frozenset({ASNs.VICTIM.value}),
        override_non_default_asn_cls_dict=frozendict(),
    ),
    as_graph_info=as_graph_info_000,
)
