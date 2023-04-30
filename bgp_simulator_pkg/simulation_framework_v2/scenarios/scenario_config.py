from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Tuple, Type

from caida_collector_pkg import AS

from .scenario_trial import ScenarioTrial
from ...simulation_engine import Announcement
from ...simulation_engine import BGPSimpleAS

pseudo_base_cls_dict: Dict[Type[AS], Type[AS]] = dict()


@dataclass(frozen=True)
class ScenarioConfig:
    """Contains information required to set up a scenario/attack

    Is reused for multiple trials (thus, frozen)
    """

    ScenarioTrialCls: ScenarioTrial
    # This is the base type of announcement for this class
    # You can specify a different base ann
    AnnCls: Type[Announcement]
    BaseASCls: Type[AS] = BGPSimpleAS
    AdoptASCls: Optional[Type[AS]] = None
    num_attackers: int = 1,
    num_victims: int = 1,
    # Adoption is equal across these atributes of the engine
    adoption_subcategory_attrs: Tuple[str, ...] = (
        "stub_or_mh_asns",
        "etc_asns",
        "input_clique_asns"
    )
    # Attackers can be chosen from this attribute of the engine
    attacker_subcategory_attr: str = "stubs_or_mh_asns"
    # Victims can be chosen from this attribute of the engine
    victim_subcategory_attr: str = "stubs_or_mh_asns"
    # ASes that are hardcoded to specific values
    hardcoded_asn_cls_dict: Dict[int, Type[AS]] = dict()

    def __post_init__(self):
        """Sets AdoptASCls if it is None

        This is done to fix the following:
        Scenario 1 has 3 BGP ASes and 1 AdoptCls
        Scenario 2 has no adopt classes, so 4 BGP
        Scenario 3 we want to run ROV++, but what were the adopting ASes from
        scenario 1? We don't know anymore.
        Instead for scenario 2, we have 3 BGP ASes and 1 Psuedo BGP AS
        Then scenario 3 will still work as expected
        """

        if self.AdoptASCls is None:
            # mypy says this is unreachable, which is wrong
            global pseudo_base_cls_dict  # type: ignore
            AdoptASCls = pseudo_base_cls_dict.get(self.BaseASCls)
            if not AdoptASCls:
                name: str = f"Psuedo {self.BaseASCls.name}".replace(" ", "")
                PseudoBaseCls = type(name, (self.BaseASCls,), {"name": name})
                pseudo_base_cls_dict[self.BaseASCls] = PseudoBaseCls
                AdoptASCls = PseudoBaseCls
            object.__setattr__(self, "AdoptASCls", AdoptASCls)
        else:
            object.__setattr__(self, "AdoptASCls", AdoptASCls)

    ##############
    # Yaml Funcs #
    ##############

    def __to_yaml_dict__(self) -> Dict[Any, Any]:
        """This optional method is called when you call yaml.dump()"""

        return asdict(self)

    @classmethod
    def __from_yaml_dict__(cls, dct, yaml_tag):
        """This optional method is called when you call yaml.load()"""

        return cls(**dct)
