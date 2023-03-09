#!/usr/bin/python3

import re
import ipaddress
import configparser
from jinja2 import Environment, FileSystemLoader

class zonegenerator:

    records=[]
    ptrrecords=[]
    ip_prefix=[]
    mask_bytes=2

    # load zonefiles, and collect A records into list of dicts, then sort elements
    def __init__(self):
        self.read_config()

        for item in self.zonefiles.split(','):
            zonename,zonefile=item.split(':')
            fh=open(zonefile,'r')

            for line in fh.readlines():
                if re.match('^\s*?(\d{10})\s*?; ?serial.*', line):
                    newserial=int(re.sub('^\s*?(\d{10})\s*?; ?serial.*$', '\\1', line).rstrip())
                    self.serial=newserial if newserial>int(self.serial) else self.serial
                if re.match('^([a-z0-9-_]+?)\s+?(?:IN)?\s+?A\s+?([\d\.]+?)$', line):
                    match=re.match('^([a-z0-9-_]+?)\s+?(?:IN)?\s+?A\s+?([\d\.]+?)$', line)
                    self.records.append({'name': match.group(1)+'.'+zonename+'.',\
                                         'ip': ipaddress.IPv4Address(match.group(2).rstrip()),\
                                         'revptr': ipaddress.IPv4Address(match.group(2).rstrip()).reverse_pointer+'.'})
            fh.close()

        # sort records by IP address
        self.records=sorted(self.records, key=lambda k: k['ip'])

    # read config params from conf file
    def read_config(self,required_params=10):
        config_num=0
        config = configparser.ConfigParser()
        try:
            config.read("crab.conf")

            for each_section in config.sections():
                for (each_key, each_val) in config.items(each_section):
                    config_num=config_num+1
                    try:
                        setattr(self, each_key, each_val)
                    except:
                        pass

            if config_num<required_params:
                print("Missing parameters! Exiting...")
                exit(1)

        except configparser.ParsingError:
            print("Parse error in config file! Exiting...")
            exit(1)

        except configparser.NoSectionError:
            print("Couldn't find all params in the conf file")
            exit(1)

    # generate ip prefixes based on subnet mask byte number
    def generate_prefixes(self):
        for i in self.records:
            first_bytes=(re.sub('^((\d+?\.){'+str(self.mask_bytes)+'}).*$', '\\1', str(i['ip']))).rstrip('.')
#            first_bytes=first_bytes.rstrip('.')
            first_bytes_rev='.'.join(reversed(first_bytes.split('.')))
            if not any(first_bytes_rev in d.values() for d in self.ip_prefix):
                self.ip_prefix.append({'orig': first_bytes, 'rev': first_bytes_rev})

    # generate rev zone files from jinja2 template
    def generate_rev_files(self):
        self.generate_prefixes()
        for prefix in self.ip_prefix:
            file_loader=FileSystemLoader('.')
            env=Environment(loader=file_loader)
            template=env.get_template('rev_zone.j2')
            output=template.render(ip_prefix=prefix, records=self.records, ttl=self.ttl, serial=self.serial, hostmaster=self.hostmaster, refresh=self.refresh, retry=self.retry, \
                                   expiry=self.expiry, minimum=self.minimum, ns1=self.ns1, ns2=self.ns2)
            fh=open(self.revzone_output_folder+'/'+prefix['orig']+'.zone', 'w')
            fh.write(output)
            fh.close()

x=zonegenerator()
x.generate_rev_files()
