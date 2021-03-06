# A simplified Snort rules parser that will be then integrated into the
# simple_ids.py app eventually
# The rules are read from snort.rules file

import sys, traceback
import re
import datetime
from pyparsing import *
from traffic_monitor import bcolors


ipAddress = Combine(Word(nums) + ('.' + Word(nums))*3)
hexint = Word(hexnums,exact=2)
specialchars = Word(alphanums+"."+"["+"]"+"$"+":"+"_"+"-"+">"+"\""+"("+")" \
                             +"\\"+";"+","+" "+"'"+"/"+"?"+"|"+"="+"*"+"!" \
                             +"{"+"}"+"<"+"&"+"^"+"~"+"%"+"*"+"+"+"#")
macAddress = Combine(hexint + (':'+hexint)*5)
identifier = Word(alphas+"_", exact=1) + Optional(Word(alphanums+"_"))
envvar     = Combine("$" + identifier)
portnum    = Word(nums) | Word(alphas) | envvar 

# action: alert, drop etc.
action     = Word(alphas) 
# src_ip/dst_ip: IP, env var like $HOME_NET or rserved wild-card like 'any'
src_ip     = (ipAddress | envvar | "any")
dst_ip     = (ipAddress | envvar | "any")
# proto: could be udp, tcp or a decimal number like 65535 (not in hex yet)
proto      = (Word(alphas) | Word(nums))
# options: A world between '(' & ')'
options    = Combine("(" + Optional(specialchars))

#Parser for a single option
option_key = Word(alphas+"_"+"-")
option_val = Word(alphanums+"."+"["+"]"+"$"+"_"+"-"+">"+"\""+"("+")" \
        +"\\"+","+" "+"'"+"/"+"?"+"|"+"="+"*"+"!"+":"+"~"\
                             +"{"+"}"+"<"+"&"+"^"+"%"+"*"+"+"+"#")
kvp = option_key + Optional(Literal(":")) + \
                    Optional(option_val) + Literal(";").suppress()
rule_option = Literal("(").suppress() + OneOrMore(kvp) + \
                    Literal(")").suppress()

""" Represents a single rule in the rules file """
class Rule:
    def __init__(self, action, proto, src_ip, dst_ip, src_port, dst_port,
            in_options):
        self.action = action
        self.proto  = proto
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.options  = {}
        option_tokens = rule_option.parseString(in_options)
        i = 0
        while i < range(len(option_tokens)):
            #print "Processing %d of %d tokens (%s)" % (i, len(option_tokens),
            #        option_tokens[i])
            if option_tokens[i + 1] == ":":
                self.options[option_tokens[i]] = option_tokens[i+2]
                if (i+3) >= len(option_tokens):
                    break
                i = i+3
            else:
                i = i+1

    """
    Checks if the given data matches "this" rule
    """
    def getMatch(self, proto="any", src_ip="any", src_port="any", dst_ip="any",
            dst_port="any", pps=-1, pkt_data=None):

        prot_match = sip_match = sport_match = 0
        dip_match = dport_match = pps_match = pkt_match = 0
        result = None

        if ((self.proto != "any") and (proto == self.proto)) or \
                (self.proto == "any"):
            prot_match = 1
        if ((self.src_ip != "any") and (src_ip == self.src_ip)) or \
                (self.src_ip == "any"):
            sip_match = 1
        if ((self.src_port != "any") and (src_port == self.src_port)) or \
                (self.src_port == "any"):
            sport_match = 1
        if ((self.dst_ip != "any") and (dst_ip == self.dst_ip)) or \
                (self.dst_ip == "any"):
            dip_match = 1

        #print "PORT : %s : %s\n" % (dst_port, self.dst_port)
        if ((self.dst_port != "any") and (str(dst_port) == self.dst_port)) or \
                (self.dst_port == "any"):
            dport_match = 1
        if "pps" in self.options:
      	    #print "actual pps "+str(pps)
	    #print "rule pps "+str(self.options["pps"])
            if ((int(self.options["pps"]) != -1 and \
                pps >= int(self.options["pps"])) or \
                    (int(self.options["pps"])== -1)):
                pps_match = 1
        else:
            pps_match = 1

        if "content" in self.options:
            if (pkt_data == None):
                pkt_match = 1
            else:
                pattern = str(self.options["content"])
                searchresult = re.search(pattern[1:len(pattern)-1], str(pkt_data)) 
                if searchresult != None:
                    pkt_match = 1
                else:
                    pkt_match = 0
        else:
            pkt_match = 1

        if (prot_match == sip_match == sport_match == dip_match == \
                dport_match == pps_match == pkt_match == 1):
            result = [ self.action ]
            if "msg" in self.options and self.action == "alert":
                result.append(self.options["msg"])
            if "reinstate" in self.options:
                result.append("reinstate")
            if "pps" in self.options and int(self.options["pps"]) != -1 and \
                    pps >= int(self.options["pps"]):
                result.append("pps")
                result.append(self.options["pps"])
            return result



    def dumpOption(self, key=""):
        if (key == ""):
            print self.options
        else:
            print "%s = %s" % (key, self.options[key])

class SnortParser:
    # Should be a singleton class - One instance is enough for the lifetime of
    # the IDS application

    # TODO: port numbers do not support range (rule in line 2427, 2574, 2942,
    # 2945-2961, 2978-2989, 3013) and list (rule in # line 2424). 
    # Need to tweak the grammar a bit to get this to work

    def __init__(self, owner, rule_file="./snort.rules"):
        """
        " Can be called with one file for light-probing rules and another for
        " deep probing rules - so not exactly a singleton as mentioned above
        """

        self.owner = owner
        self.rules = []

        # Snort rules take the form:
        #   action proto src_ip src_port direction dst_ip dst_port (options)
        snort_grammar = action + proto + src_ip + portnum + "->" + \
               dst_ip + portnum + options

        fp_rules = open(rule_file, 'r')
        index = 0
        for rule in fp_rules:
            # Ignore comments
            if ((re.search('^ *#', rule) == None) and 
                (re.search('^ *$', rule) == None)):
                try:
                    tokens = snort_grammar.parseString(rule)
                    self.rules.append(Rule(tokens[0], tokens[1], tokens[2],
                            tokens[5], tokens[3], tokens[6], tokens[7]))
                    index = index + 1
                except:
                    print "\nSyntax error at line %d in rule: %s" % \
                            (index, rule)
                    traceback.print_exc(file=sys.stdout)
                    return "error"
                    break

        self.num_rules = index;
        print "Total number of rules from %s: %d : %d" % (rule_file, 
                                                          self.num_rules, 
                                                          len(self.rules))

    def dumpRules(self):
        index = 0
        while (index < len(self.rules)):
            rule = self.rules[index]
            print "\n%d: %s %s %s -> %s %s %s" % (index, rule.action,
                    rule.src_ip, rule.src_port, rule.dst_ip, rule.dst_port,
                    rule.options)
            index = index + 1

    def dumpOptions(self):
        index = 0
        while (index < len(self.rules)):
            rule = self.rules[index]
            rule.dumpOption(key="msg")
            index = index + 1

    def getMatch(self, proto="any", src_ip="any", src_port="any", dst_ip="any",
            dst_port="any", pps=-1, pkt_data=None):
        index = 0
        while (index < len(self.rules)):
            rule = self.rules[index]
            result = rule.getMatch(proto, src_ip, 
                    src_port, dst_ip, dst_port, pps, pkt_data)
            index = index + 1
            if result == None:
                next
            else:
                return result

    """ 
    " Programs only drop flows if required. The caller needs to take necessary
    " action for all other cases
    " Returns a list if a match is found, else None
    " The list could be [ "alert", "this is h1->h3", "reinstate" ] or ["drop"]
    " etc. based on the rule format
    """
    def impose(self, datapath, in_port, out_port, proto="any", src_ip="any", 
            src_port="any", dst_ip="any", dst_port="any", pps=-1, pkt_data=None):

        drop_flag = False
        reinstate_flag = False
        result = self.getMatch(proto, src_ip, src_port, dst_ip, dst_port, pps,
                pkt_data)
	#print ">>>>>> "+str(result)
        if (result != None):
            if "alert" in result: 
                # Can hook into email option here too for alerts
		f = open('ryu/app/AdaptiveIDS/alert_output', 'a')
		f.write(result[1]+"\n")
                print(bcolors.WARNING + '[ '+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+' ] ' + "!! ALERT : %s !!" % result[1] + bcolors.ENDC)
                ids_alerts_log = open('./ryu/app/AdaptiveIDS/ids_hits.alerts', 'a')
                ids_alerts_log.write('<font color="brown">'+ '[ '+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+' ] ' + 'ALERT: '+ str(result[1]) +'</font><br/>')
                ids_alerts_log.close()
            if "drop" in result:
                drop_flag = True
                actions = ""
            else:
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            if "reinstate" in result:
                reinstate_flag = True

        if drop_flag == True:
            self.owner.send_ip_flow(datapath.ofproto.OFPFC_ADD, 
                    in_port, out_port, proto=proto, 
                    src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, 
                    dst_port=dst_port, drop=drop_flag)
            self.owner.send_ip_flow(datapath.ofproto.OFPFC_MODIFY, 
                    in_port, out_port, proto=proto, 
                    src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, 
                    dst_port=dst_port, drop=drop_flag)
            flow = self.owner.flows.addflow(datapath, proto, src_ip, src_port, 
                    dst_ip, dst_port, in_port=in_port,  out_port=out_port,
                                matches_rule=True,
                                reinstate=reinstate_flag)
            if pps != -1 and "pps" in result:
                flow.trigger = True
                flow.triggerPPS = int(result[result.index("pps") + 1])
                print "detected pps (%d) is greater than pps in rule (%d)" % (pps, flow.triggerPPS)
        return result




# Testing
#parser = SnortParser(rule_file="./light_probe.rules")
#parser = SnortParser()
#parser.dumpOptions()

