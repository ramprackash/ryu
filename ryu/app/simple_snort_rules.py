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
                             +"{"+"}"+"<")
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

class Rule:
    def __init__(self, action, proto, src_ip, dst_ip, src_port, dst_port,
            options):
        self.action = action
        self.proto  = proto
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.options  = options

class SnortParser:
    # Should be a singleton class - One instance is enough for the lifetime of
    # the IDS application

    # TODO: port numbers do not support range (rule in line 2427, 2574, 2942,
    # 2945-2961, 2978-2989, 3013) and list (rule in # line 2424). 
    # Need to tweak the grammar a bit to get this to work

    def __init__(self, rule_file="./snort.rules"):
        """
        " Can be called with one file for light-probing rules and another for
        " deep probing rules - so not exactly a singleton as mentioned above
        """

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
                    break

        self.num_rules = index;
        print "Total number of rules: %d : %d" % (self.num_rules, len(self.rules))

    def dumpRules(self):
        index = 0;
        while (index < len(self.rules)):
            rule = self.rules[index]
            print "\n%d: %s %s %s -> %s %s %s" % (index, rule.action,
                    rule.src_ip, rule.src_port, rule.dst_ip, rule.dst_port,
                    rule.options)
            index = index + 1

    def getRules(self):
        """ 
        " API for IDS application to get the rules configured int the system
        """
        # TODO


# Testing
parser = SnortParser()
parser.dumpRules()

