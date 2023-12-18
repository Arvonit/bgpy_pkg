from bgpy.as_graphs.base import ASGraphConstructor, ASGraphInfo


class CAIDAASGraphConstructor(ASGraphConstructor):

    # Add an optional default to ASGraphCollectorCls and ASGraphCls
    def __init__(
        self,
        ASGraphCollectorCls: type[ASGraphCollector] = CAIDAASGraphCollector
        ASGraphCls: type[ASGraph] = CAIDAASGraph,
        as_graph_collector_kwargs = frozendict(),
        as_graph_kwargs = frozendict()
        tsv_path: Optional[Path] = None,
    ) -> None:

        super().__init__(
            ASGraphCollectorCls,
            ASGraphCls,
            as_graph_collector_kwargs = as_graph_collector_kwargs
            as_graph_kwargs = as_graph_kwargs
            tsv_path: tsv_path,
        )

    ####################
    # Abstract methods #
    ####################
    def _get_as_graph_info(self, dl_path: Path) -> ASGraphInfo:
        """Gets AS Graph info from the downloaded file"""

        input_clique_asns: set[int] = set()
        ixp_asns: set[int] = set()
        # Customer provider links
        cp_links: set[CPLink] = set()
        # Peer links
        peer_links: set[PeerLink] = set()

        with dl_path.open() as f:
            for line in f:
                # Get Caida input clique. See paper on site for what this is
                if line.startswith("# input clique"):
                    self._extract_input_clique_asns(line, input_clique_asns)
                # Get detected Caida IXPs. See paper on site for what this is
                elif line.startswith("# IXP ASes"):
                    self._extract_ixp_asns(line, ixp_asns)
                # Not a comment, must be a relationship
                elif not line.startswith("#"):
                    # Extract all customer provider pairs
                    if "-1" in line:
                        self._extract_provider_customers(line, cp_links)
                    # Extract all peers
                    else:
                        self._extract_peers(line, peer_links)

        return ASGraphInfo(
            customer_provider_links=frozenset(cp_links),
            peer_links=frozenset(peer_links),
            ixp_asns=frozenset(ixp_asns),
            input_clique_asns=frozenset(input_clique_asns)
        )

    def _get_as_graph(self, as_graph_info: ASGraphInfo) -> ASGraph:
        """Creates and returns the ASGraph"""

        return = self.ASGraphCls(
            cp_links,
            peer_links,
            ixp_asns=ixp_asns,
            input_clique=input_clique,
            **self.as_graph_kwargs
        )

    #################
    # Parsing funcs #
    #################

    def _extract_input_clique_asns(self, line: str, input_clique_asns: set[int]) -> None:
        """Adds all ASNs within input clique line to ases dict"""

        # Gets all input ASes for clique
        for asn in line.split(":")[-1].strip().split(" "):
            # Insert AS into graph
            input_clique_asns.add(int(asn))

    def _extract_ixp_asns(self, line: str, ixp_asns: set[int]) -> None:
        """Adds all ASNs that are detected IXPs to ASes dict"""

        # Get all IXPs that Caida lists
        for asn in line.split(":")[-1].strip().split(" "):
            ixp_asns.add(int(asn))

    def _extract_provider_customers(self, line: str, cp_links: set[CPLink]) -> None:
        """Extracts provider customers: <provider-as>|<customer-as>|-1"""

        provider_asn, customer_asn, _, source = line.split("|")
        cp_links.add(
            CPLink(customer_asn=int(customer_asn), provider_asn=int(provider_asn))
        )

    def _extract_peers(self, line: str, peer_links: set[PeerLink]) -> None:
        """Extracts peers: <peer-as>|<peer-as>|0|<source>"""

        peer1_asn, peer2_asn, _, source = line.split("|")
        peer_links.add(PeerLink(int(peer1_asn), int(peer2_asn)))
