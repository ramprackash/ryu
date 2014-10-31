# A simplified Snort rules parser that will be then integrated into the
# simple_ids.py app eventually
# The rules are read from snort.rules file

import sys, traceback
import re
from pyparsing import *


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
kvp        = option_key + Optional(Literal(":")) + Optional(option_val) + Literal(";").suppress()
rule_option = Literal("(").suppress() + OneOrMore(kvp) + Literal(")").suppress()

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

    def getMatch(self, proto="any", src_ip="any", src_port="any", dst_ip="any", 
            dst_port="any", pps=-1):
        #print("Checking %s:%s:%d" % (self.src_ip, self.dst_ip, int(self.options["pps"])))
        prot_match = sip_match = sport_match = dip_match = dport_match = pps_match = 0
        result = None

        if ((proto != "any") and (proto == self.proto)) or (proto == "any"):
            prot_match = 1
        if ((src_ip != "any") and (src_ip == self.src_ip)) or (src_ip == "any"):
            sip_match = 1
        if ((src_port != "any") and (src_port == self.src_port)) or (src_port == "any"):
            sport_match = 1
        if ((dst_ip != "any") and (dst_ip == self.dst_ip)) or (dst_ip == "any"):
            dip_match = 1
        if ((dst_port != "any") and (dst_port == self.dst_port)) or (dst_port == "any"):
            dport_match = 1
        if "pps" in self.options:
            if ((pps != -1) and (pps >= int(self.options["pps"]))) or (pps == -1):
                pps_match = 1
        else:
            pps_match = 1
        if prot_match == sip_match == sport_match == dip_match == dport_match == pps_match == 1:
            if "msg" in self.options and self.action == "alert":
                return [self.action, self.options["msg"]]
            else:
                return [self.action]
        else:
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
                    print "\nSyntax error at line %d in rule: %s" % (index, rule)
                    traceback.print_exc(file=sys.stdout)
                    return "error"
                    break

        self.num_rules = index;
        print "Total number of rules from %s: %d : %d" % (rule_file, self.num_rules, len(self.rules))

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

    def getRules(self):
        """ 
        " API for IDS application to get the rules configured int the system
        """
        # TODO

    def getMatch(self, proto="any", src_ip="any", src_port="any", dst_ip="any", 
            dst_port="any", pps=0):
        index = 0
        while (index < len(self.rules)):
            rule = self.rules[index]
            result = rule.getMatch(proto, src_ip, 
                    src_port, dst_ip, dst_port, pps)
            index = index + 1
            if result == None:
                next
            else:
                return result


# Testing
#parser = SnortParser(rule_file="./light_probe.rules")
#parser = SnortParser()
#parser.dumpOptions()

