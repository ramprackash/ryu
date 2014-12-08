
import logging

import json
from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication



# REST API
#

# delete a group entry
# POST /stats/groupentry/delete
#
#
# send a experimeter message
# POST /stats/experimenter/<dpid>


class AdIDSController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(AdIDSController, self).__init__(req, link, data, **config)
        

    def get_logs(self, req, **_kwargs):
        #print("AdIDSController - get_logs")
        resp = ""  
        resp_file = open("./ryu/app/AdaptiveIDS/tmlogs.txt","r")
 
        r_lines = resp_file.readlines()	
        resp_body = ''
        for r_line in r_lines:
            resp_body = resp_body + r_line
        return Response(content_type='text', body=resp_body)
        '''
        dp = self.dpset.get(int(dpid))
        if dp is None:
            return Response(status=404)

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            flows = ofctl_v1_0.get_flow_stats(dp, self.waiters)
        elif dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flows = ofctl_v1_2.get_flow_stats(dp, self.waiters)
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flows = ofctl_v1_3.get_flow_stats(dp, self.waiters)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)
        print("OFCTL-get_flow_stats")
        print(str(flows))
        body = json.dumps(flows)
        print("OFCTL-get_flow_stats - json")
        print(str(body))
        return (Response(content_type='application/json', body=body))'''

    def get_lp_rules(self, req, **_kwargs):
        #print("AdIDSController - get_logs")
        resp_file = open("./ryu/app/AdaptiveIDS/light_probe.rules","r")
 
        r_lines = resp_file.readlines()	
        resp_body = ''
        for r_line in r_lines:
            resp_body = resp_body + r_line
        return Response(content_type='text', body=resp_body)

    def get_dp_rules(self, req, **_kwargs):
        #print("AdIDSController - get_logs")
        resp_file = open("./ryu/app/AdaptiveIDS/deep_probe.rules","r")
 
        r_lines = resp_file.readlines()	
        resp_body = ''
        for r_line in r_lines:
            resp_body = resp_body + r_line
        return Response(content_type='text', body=resp_body)

    def get_portscan(self, req, **_kwargs):
        #print("AdIDSController - get_logs")
        resp_file = open("./ryu/app/AdaptiveIDS/portscan.report","r")
 
        r_lines = resp_file.readlines()	
        resp_body = ''
        for r_line in r_lines:
            resp_body = resp_body + r_line
        return Response(content_type='text', body=resp_body)

    def get_alerts(self, req, **_kwargs):
        #print("AdIDSController - get_logs")
        resp_file = open("./ryu/app/AdaptiveIDS/ids_hits.alerts","r")
 
        r_lines = resp_file.readlines()	
        resp_body = ''
        for r_line in r_lines:
            resp_body = resp_body + r_line
        return Response(content_type='text', body=resp_body)


class RestIDSApi(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(RestIDSApi, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        self.data = {}
        mapper = wsgi.mapper

        wsgi.registory['AdIDSController'] = self.data
        path = '/ids'
        uri = path + '/logs'
        mapper.connect('ids', uri,
                       controller=AdIDSController, action='get_logs',
                       conditions=dict(method=['GET']))
        uri = path + '/portscan'
        mapper.connect('ids', uri,
                       controller=AdIDSController, action='get_portscan',
                       conditions=dict(method=['GET']))
        uri = path + '/idsalerts'
        mapper.connect('ids', uri,
                       controller=AdIDSController, action='get_alerts',
                       conditions=dict(method=['GET']))
        uri = path + '/lprules'
        mapper.connect('ids', uri,
                       controller=AdIDSController, action='get_lp_rules',
                       conditions=dict(method=['GET']))
        uri = path + '/dprules'
        mapper.connect('ids', uri,
                       controller=AdIDSController, action='get_dp_rules',
                       conditions=dict(method=['GET']))




