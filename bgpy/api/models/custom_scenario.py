from typing import Optional, Union
from bgpy.enums import SpecialPercentAdoptions
from bgpy.simulation_engine import BaseSimulationEngine
from bgpy.simulation_framework import Scenario, ScenarioConfig
from bgpy.simulation_framework.scenarios.preprocess_anns_funcs import (
    PREPROCESS_ANNS_FUNC_TYPE,
    noop,
)


class CustomScenario(Scenario):
    """
    Allows API users to create their own scenario using self-defined announcements and
    ROAs.
    """

    def __init__(
        self,
        *,
        scenario_config: ScenarioConfig,
        percent_adoption: Union[float, SpecialPercentAdoptions] = 0,
        engine: Optional[BaseSimulationEngine] = None,
        prev_scenario: Optional["Scenario"] = None,
        preprocess_anns_func: PREPROCESS_ANNS_FUNC_TYPE = noop,
    ):
        super().__init__(
            scenario_config=scenario_config,
            percent_adoption=percent_adoption,
            engine=engine,
            prev_scenario=prev_scenario,
            preprocess_anns_func=preprocess_anns_func,
        )
        self.announcements = self._add_roa_info_to_anns(
            announcements=self.scenario_config.override_announcements,
            engine=engine,
            prev_scenario=prev_scenario,
        )

    def _get_announcements(self, *args, **kwargs):
        # Announcements will be populated from the scenario config's
        # override_announcements
        if len(self.scenario_config.override_announcements) == 0:
            raise ValueError("Scenario config must specify announcements")
        return ()
