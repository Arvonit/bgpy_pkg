from collections import defaultdict

from lib_caida_collector import AS

from .ann_containers import LocalRib
from .ann_containers import RIBsIn, RIBsOut
from .ann_containers import SendQueue, RecvQueue
from ..enums import Relationships
from ..announcement import Announcement as Ann
from .bgp_as import BGPAS


class BGPRIBsAS(BGPAS):
    __slots__ = []
    #__slots__ = ["local_rib", "recv_q", "ribs_in", "ribs_out", "send_q"]

    def __init__(self, *args, **kwargs):
        super(BGPRIBsAS, self).__init__(*args, **kwargs)
        self.ribs_in = RIBsIn()
        self.ribs_out = RIBsOut()
        self.send_q = SendQueue()

    def _propagate(self, propagate_to: Relationships, send_rels: list):
        """Propogates announcements to other ASes

        send_rels is the relationships that are acceptable to send
        """
        # _policy_propagate and _add_ann_to_q have been overriden
        # So that instead of propagating, announcements end up in the send_q
        # Send q contains both announcements and withdrawals
        self._populate_send_q(propagate_to, send_rels)

        # Send announcements/withdrawals and add to ribs out
        self._send_anns(propagate_to)

    def _populate_send_q(self, propagate_to, send_rels):
        # Process_outgoing_ann is overriden so this just adds to send q
        return super(BGPRIBsAS, self)._propagate(propagate_to, send_rels)

    def _policy_propagate(self, neighbor, ann, *args, **kwargs):
        """Don't send what we've already sent"""

        ribs_out_ann = self.ribs_out.get_ann(neighbor.asn, ann.prefix)
        return ann.prefix_path_attributes_eq(ribs_out_ann)

    def _process_outgoing_ann(self, neighbor, ann, *args):
        self.send_q.add_ann(neighbor.asn, ann)

    def _send_anns(self, propagate_to: Relationships):
        """Sends announcements and populates ribs out"""

        neighbors = getattr(self, propagate_to.name.lower())

        for (neighbor, prefix, ann) in self.send_q.info(neighbors):
            neighbor.recv_q.add_ann(ann)
            # Update Ribs out if it's not a withdraw
            if not ann.withdraw:
               self.ribs_out.add_ann(neighbor.asn, ann)
        for neighbor in getattr(self, propagate_to.name.lower()):
            self.send_q.reset_neighbor(neighbor.asn)

    def process_incoming_anns(self,
                              recv_relationship: Relationships,
                              *args,
                              propagation_round=None,
                              # Usually None for attack
                              attack=None,
                              reset_q=True,
                              **kwargs):
        """Process all announcements that were incoming from a specific rel"""

        for prefix, anns in self.recv_q.prefix_anns():

            # Get announcement currently in local rib
            local_rib_ann = self.local_rib.get_ann(prefix)
            current_best_ann = local_rib_ann
            current_best_ann_processed = True

            # Announcement will never be overriden, so continue
            if getattr(current_best_ann, "seed_asn", None):
                continue

            # For each announcement that is incoming
            for ann in anns:
                # withdrawals
                err = "Recieved two withdrawals from the same neighbor"
                assert len([x.as_path[0] for x in anns if x.withdraw]) ==\
                    len(set([x.as_path[0] for x in anns if x.withdraw])), err

                err = "Recieved two NON withdrawals from the same neighbor"
                assert len([x.as_path[0] for x in anns if not x.withdraw]) ==\
                    len(set([x.as_path[0] for x in anns
                             if not x.withdraw])), err

               # Always add to ribs in if it's not a withdrawal
                if not ann.withdraw:
                    err = ("you should never be replacing anns. "
                           "You should always withdraw first, "
                           "have it be blank, then add the new one")
                    assert self.ribs_in.get_unprocessed_ann_recv_rel(
                        ann.as_path[0], prefix) is None, err

                    self.ribs_in.add_unprocessed_ann(ann, recv_relationship)

                # If it's valid, process it
                if self._valid_ann(ann, recv_relationship):
                    if ann.withdraw:
                        self._process_incoming_withdrawal(ann, recv_relationship)

                    else:
                        new_ann_is_better = self._new_ann_better(current_best_ann,
                                                                 current_best_ann_processed,
                                                                 recv_relationship,
                                                                 ann,
                                                                 False,
                                                                 recv_relationship)
                        # If the new priority is higher
                        if new_ann_is_better:
                            current_best_ann = ann
                            current_best_ann_processed = False

            if local_rib_ann is not None and current_best_ann_processed is False:
                # Best ann has already been processed
                withdraw_ann = local_rib_ann.copy(withdraw=True)
                self._withdraw_ann_from_neighbors(withdraw_ann)
                err = "withdrawing an announcement that is identical to new ann"
                assert not withdraw_ann.prefix_path_attributes_eq(
                    self._deep_copy_ann(ann, recv_relationship)), err

            # We have a new best!
            if current_best_ann_processed is False:
                current_best_ann = self._deep_copy_ann(ann, recv_relationship)
                # Save to local rib
                self.local_rib.add_ann(current_best_ann)

        self._reset_q(reset_q)

    def _process_incoming_withdrawal(self, ann, recv_relationship):
        prefix = ann.prefix
        neighbor = ann.as_path[0]
        # Return if the current ann was seeded (for an attack)
        local_rib_ann = self.local_rib.get_ann(prefix)

        err = "Trying to withdraw seeded ann {local_rib_ann.seed_asn}"
        assert not ((local_rib_ann is not None)
                    and ((ann.prefix_path_attributes_eq(local_rib_ann))
                    and (local_rib_ann.seed_asn is not None))), err


        current_ann_ribs_in, _ =\
            self.ribs_in.get_unprocessed_ann_recv_rel(neighbor, prefix)

        err = (f"Cannot withdraw ann that was never sent.\n\t "
               f"Ribs in: {current_ann_ribs_in}\n\t withdraw: {ann}")
        assert ann.prefix_path_attributes_eq(current_ann_ribs_in), err
        
        # Remove ann from Ribs in
        self.ribs_in.remove_entry(neighbor, prefix)

        # Remove ann from local rib
        withdraw_ann = self._deep_copy_ann(ann,
                                           recv_relationship,
                                           withdraw=True)
        if withdraw_ann.prefix_path_attributes_eq(
            self.local_rib.get_ann(prefix)):

            self.local_rib.remove_ann(prefix)
            # Also remove from neighbors
            self._withdraw_ann_from_neighbors(withdraw_ann)

        best_ann = self._select_best_ribs_in(prefix)
        
        # Put new ann in local rib
        if best_ann is not None:
            self.local_rib.add_ann(best_ann)

        err = "Best ann should not be identical to the one we just withdrew"
        assert not withdraw_ann.prefix_path_attributes_eq(best_ann), err

    def _withdraw_ann_from_neighbors(self, withdraw_ann):
        """Withdraw a route from all neighbors.

        This function will not remove an announcement from the local rib, that
        should be done before calling this function.

        Note that withdraw_ann is a deep copied ann
        """
        assert withdraw_ann.withdraw is True
        # Check ribs_out to see where the withdrawn ann was sent
        for send_neighbor in self.ribs_out.neighbors():
            # If the two announcements are equal
            if withdraw_ann.prefix_path_attributes_eq(
                self.ribs_out.get_ann(send_neighbor, withdraw_ann.prefix)):

                # Delete ann from ribs out
                self.ribs_out.remove_entry(send_neighbor, withdraw_ann.prefix)
                self.send_q.add_ann(send_neighbor, withdraw_ann)

        # We may not have sent the ann yet, it may just be in the send queue
        # and not ribs out
        # We want to cancel out any anns in the send_queue that match the wdraw
        for neighbor_obj in self.peers + self.customers + self.providers:
            send_info = self.send_q.get_send_info(neighbor_obj,
                                                  withdraw_ann.prefix)
            if send_info is None or send_info.ann is None:
                continue
            elif send_info.ann.prefix_path_attributes_eq(withdraw_ann):
                send_info.ann = None

    def _select_best_ribs_in(self, prefix):
        """Selects best ann from ribs in. Remember, ribs in anns are NOT deep copied"""

        # Get the best announcement
        best_unprocessed_ann = None
        best_recv_relationship = None
        for (new_unprocessed_ann,
             new_recv_relationship) in self.ribs_in.get_ann_infos(prefix):

            if self._new_ann_better(best_unprocessed_ann,
                                    False,
                                    best_recv_relationship,
                                    new_unprocessed_ann,
                                    False,
                                    new_recv_relationship):
                best_unprocessed_ann = new_unprocessed_ann
                best_recv_relationship = new_recv_relationship

        if best_unprocessed_ann is not None:
            return self._deep_copy_ann(best_unprocessed_ann, best_recv_relationship)
        else:
            return None