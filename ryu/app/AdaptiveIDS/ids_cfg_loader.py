from ConfigParser import SafeConfigParser
from ConfigParser import NoSectionError
from ConfigParser import NoOptionError

class IDSCfgLoader:
    def __init__(self, filename='./ryu/app/AdaptiveIDS/ids.cfg'):
        self.parser = SafeConfigParser()
        self.cfg_filename = filename
        self.cfg_params = {}

    def load_single_cfg_param(self, section_name, option_name, datatype='str'):
        parse_success = True
        try:
            cfg_val = self.parser.get(section_name, option_name)
        except NoOptionError:
            print('Exception in parsing %s parameter in %s section. Fix the config file!' %(option_name, section_name))
            return False
        except NoSectionError:
            print('Exception in parsing %s parameter in %s section. Fix the config file!' %(option_name, section_name))
            return False
        if datatype == 'int':
            self.cfg_params[option_name] = int(cfg_val)
        else:
            self.cfg_params[option_name] = cfg_val
        return True

    def load_all_cfg_params(self):
        self.parser.read(self.cfg_filename)
        if not self.load_single_cfg_param('ids_cfg', 'fsm_timer', 'int'):
            return False
        if not self.load_single_cfg_param('ids_cfg', 'lp_rules_file'):
            return False
        if not self.load_single_cfg_param('ids_cfg', 'dp_rules_file'):
            return False 
        if not self.load_single_cfg_param('ids_cfg', 'flow_stats_interval', 'int'):
            return False
        if not self.load_single_cfg_param('ids_cfg', 'lp_sampling_ratio', 'int'):
            return False
        if not self.load_single_cfg_param('ids_cfg', 'port_scan_window', 'int'):
            return False
        return True

    def get_all_cfg_params(self):
        return self.cfg_params
        

