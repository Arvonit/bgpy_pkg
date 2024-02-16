from pydantic import BaseModel, ValidationInfo, model_validator, conlist
from typing import Optional
from bgpy.as_graphs import ASGraphInfo, CustomerProviderLink, PeerLink


class APIGraph(BaseModel):
    # provider: cp_links[i][0], customer: cp_links[i][1]
    cp_links: list[conlist(int, min_length=2, max_length=2)]  # type: ignore
    peer_links: list[conlist(int, min_length=2, max_length=2)]  # type: ignore
    propagation_ranks: list[list[int]] = []

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
            diagram_ranks=tuple(tuple(asns) for asns in self.propagation_ranks),
        )

    # @model_validator(mode="after")
    # def check_graph_size(self, info: ValidationInfo) -> "Graph":
    #     """
    #     Ensures the graph has at most 100,000 ASes.
    #     """
    #     # TODO: Need a more robust way of rejecting without counting all the nodes
    #     unique_nodes = set()
    #     for link in self.cp_links + self.peer_links:
    #         unique_nodes.update(link)
    #     size = len(unique_nodes)

    #     if size > 100_000:
    #         raise ValueError(f"Graph must have at most 100,000 ASes, not {size:,}")

    #     return self
