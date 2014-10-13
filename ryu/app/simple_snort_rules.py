# A simplified Snort rules parser that will be then integrated into the
# simple_ids.py app eventually
# The rules are read from snort.rules file

import sys, traceback
import re
from pyparsing import *


#from ryu.base import app_manager
#from ryu.controller import ofp_event
#from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
#from ryu.controller.handler import set_ev_cls
#from ryu.ofproto import ofproto_v1_3
#from ryu.lib.packet import packet
#from ryu.lib.packet import ethernet

# TODO: port numbers do not support range (rule in line 2427, 2574, 2942,
# 2945-2961, 2978-2989, 3013) and list (rule in # line 2424). 
# Need to tweak the grammar a bit to get this to work

ipAddress = Combine(Word(nums) + ('.' + Word(nums))*3)
hexint = Word(hexnums,exact=2)
specialchars = Word(alphanums+"."+"["+"]"+"$"+":"+"_"+"-"+">"+"\""+"("+")" \
                             +"\\"+";"+","+" "+"'"+"/"+"?"+"|"+"=")
macAddress = Combine(hexint + (':'+hexint)*5)
identifier = Word(alphas+"_", exact=1) + Optional(Word(alphanums+"_"))
envvar     = Combine("$" + identifier)
portnum    = Word(nums) | Word(alphas) | envvar 
options    = Combine("(" + Optional(specialchars))

#Snort rules take the form:
#              action proto src_ip src_port direction dst_ip dst_port (options)
snort_grammar = Word(alphas) + (Word(alphas) | Word(nums)) + \
               (ipAddress | envvar | "any") + portnum + "->" + \
               (ipAddress | envvar | "any") + portnum + options


rules_file = open('./snort.rules', 'r')
line = 0
for rule in rules_file:
    line = line + 1
    # Ignore comments
    if ((re.search('^ *#', rule) == None) and 
            (re.search('^ *$', rule) == None)):
        try:
            tokens = snort_grammar.parseString(rule)
            print "Tokens: %s" % tokens
        except:
            print
            print "\nSyntax error at line %d in rule: %s" % (line, rule)
            traceback.print_exc(file=sys.stdout)
            break
