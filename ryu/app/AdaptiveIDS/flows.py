
class Flow:
    def __init__(self, dp, proto="any", sip="any", sport="any", dip="any",
                 dport="any", in_port="any", out_port="any", 
                 matches_rule="any", reinstate=False):
        self.dp  = dp
        self.proto = proto
        self.sip   = sip
        self.dip   = dip
        self.sport = sport
        self.dport = dport
        self.in_port = in_port
        self.out_port = out_port
        self.matches_rule = matches_rule
        self.reinstate = reinstate
        self.hitcount = 0
        self.bytecount  = 0
        self.avgpkts  = 0
        self.trigger = False
        self.triggerPPS = -2

    def matches(self, proto, sip, sport, dip, dport, out_port="any",
             matches_rule="any"):
         if (self.proto != proto or self.sip != sip or self.sport != sport or
                self.dip != dip or self.dport != dport):
             return False

         op_match = mrule_match = iaction_match = 0
         if out_port == "any" or out_port == self.out_port:
             op_match = 1
         if matches_rule == "any" or matches_rule == self.matches_rule:
             mrule_match = 1

         if op_match == mrule_match == 1:
             return True

    def is_reinstate(self):
         return self.reinstate

class Flows:
    def __init__(self, owner):
        self._flows = {}
        self.owner = owner

    def addflow(self, dp, proto, sip, sport, dip, dport, in_port="any", 
            out_port="any", matches_rule="any", reinstate=False):
        flow = Flow(dp, proto, sip, sport, dip, dport, in_port, out_port,
                    matches_rule, reinstate)
        key_tuple = (str(dp.id), str(sip), str(dip), str(proto), str(sport),
                    str(dport))
        self._flows[key_tuple] = flow
        return flow

    def delflow(self, flow):
        key_tuple = (str(flow.dp.id), str(flow.sip), str(flow.dip),
                str(flow.proto), str(flow.sport), str(flow.dport))
        if key_tuple not in self._flows.keys():
            return
        self.owner.send_ip_flow(flow.dp.ofproto.OFPFC_DELETE, 
                flow.in_port, flow.out_port, proto=flow.proto, 
                src_ip=flow.sip, src_port=flow.sport, dst_ip=flow.dip,
                dst_port=flow.dport, drop=True)
        del self._flows[key_tuple]

    def getflow(self, dp="any", sip="any", dip="any", proto="any", sport="any",
            dport="any"):
        key_tuple = (str(dp.id), str(sip), str(dip), str(proto), str(sport),
                    str(dport))
        if key_tuple not in self._flows.keys():
            return None
        return self._flows[key_tuple]

    def cleanup(self):
        for key_tuple in self._flows.keys():
            flow = self._flows[key_tuple]
            if flow.is_reinstate():
                print "Reinstating flow %s -> %s" % (flow.in_port, flow.out_port)
                self.owner.send_ip_flow(flow.dp.ofproto.OFPFC_DELETE, 
                        flow.in_port, flow.out_port, proto=flow.proto, 
                        src_ip=flow.sip, src_port=flow.sport, dst_ip=flow.dip,
                        dst_port=flow.dport, drop=False)
                del self._flows[key_tuple]

