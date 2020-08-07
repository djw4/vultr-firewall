#!/usr/bin/env python3
import os
import sys
import json
import requests
from loguru import logger as logging

headers = {'API-Key': os.environ['VULTR_API_KEY']}

def firewall_list_groups():
  """Lists all firewall groups in the authorised account."""
  url = 'https://api.vultr.com/v1/firewall/group_list'
  r = requests.get(url, headers=headers)
  return r.json()

def firewall_list_rules(firewall_id):
  """Lists all firewall rules in a given firewall group."""
  url = str('https://api.vultr.com/v1/firewall/rule_list?FIREWALLGROUPID={}&direction=in&ip_type=v4'.format(firewall_id))
  r = requests.get(url, headers=headers)
  return r.json()

def firewall_create_rule(firewall_id, protocol, subnet, subnet_size, port, notes):
  """Creates new firewall rule in a firewall group."""
  url = 'https://api.vultr.com/v1/firewall/rule_create'
  data = {
    'FIREWALLGROUPID':firewall_id,
    'direction':'in',
    'ip_type':'v4',
    'protocol':protocol,
    'subnet':subnet,
    'subnet_size':subnet_size,
    'port':port,
    'notes':notes
    }
  logging.debug('Sending request data = {}'.format(data))
  r = requests.post(url, headers=headers, data=data)
  return r.json()

def firewall_delete_rule(firewall_id, rule):
  """Deletes a firewall rule from a firewall group."""
  url = 'https://api.vultr.com/v1/firewall/rule_delete'
  data = {
    'FIREWALLGROUPID':firewall_id,
    'rulenumber':rule
  }
  logging.debug('Sending request data = {}'.format(data))
  r = requests.post(url, headers=headers, data=data)
  return r

def whatismyip():
  """Checks against ipinfo.io to retrieve the current public IP address"""
  url = 'https://ipinfo.io'
  r = requests.get(url).json()
  return r['ip']

def main():
  """
  Main script operations:
  - Check for the existence of a known firewall
  - Gather the current public IP address
  - Check the rules contained within that firewall
  - Check the rule contents to see if the current public IP is listed
  - If not listed, add accordingly, removing all other /32 entries.
  """
  logging.info('** Starting script execution **')
  logging.debug('Requesting Firewall_Groups')
  Firewall_Groups = firewall_list_groups()
  logging.debug('Retrieved Firewall_Groups = {}'.format(Firewall_Groups))
  Firewall_Name = os.environ['VULTR_FWGROUP_NAME']
  logging.debug('Searching for Firewall_Name = {}'.format(Firewall_Name))
  Firewall_ID = None
  TCP_PORTS = os.environ['TCP_PORTS'].split(',')
  UDP_PORTS = os.environ['UDP_PORTS'].split(',')

  for f in Firewall_Groups.keys():
    logging.debug('Checking Firewall_ID = {}'.format(f))
    if Firewall_Groups[f]['description'] in Firewall_Name:
      Firewall_ID = Firewall_Groups[f]['FIREWALLGROUPID']
      break
  
  if Firewall_ID is not None:
    logging.info('SUCCESS - Retrieved Firewall_ID = {}'.format(Firewall_ID))
  else:
    logging.error('Could not match the requested firewall name; {} .. exiting'.format(Firewall_Name))
    sys.exit(1)
  
  logging.debug('Requesting current IP address using \'https://ipinfo.io\'')
  try:
    Current_IP = whatismyip()
    logging.info('SUCCESS - Retrieved Current_IP = {}'.format(Current_IP))
  except Exception as err:
    logging.exception('Could not request current IP address .. {}'.format(err))
    sys.exit(1)

  logging.debug('Requesting Firewall_Rules for {}'.format(Firewall_ID))
  try:
    Firewall_Rules = firewall_list_rules(Firewall_ID)
    logging.debug('Retrieved Firewall_Rules = {}'.format(Firewall_Rules))
  except Exception as err:
    logging.exception('Could not request current IP address .. {}'.format(err))
    sys.exit(1)

  create_Rules = True
  logging.debug('Checking Firewall_Rules for {}'.format(Current_IP))
  for rule in Firewall_Rules.keys():
    logging.debug('Checking rule = {}'.format(rule))
    if Firewall_Rules[rule]['subnet'] in Current_IP:
      logging.info('SUCCESS - Found {} listed as {} / {}'.format(Current_IP, Firewall_ID, rule))
      create_Rules = False
      break

  if create_Rules:
    logging.info('FAILED Could not find {} listed in {}'.format(Current_IP, Firewall_ID))
    logging.debug('Removing all /32 rules for {}'.format(Firewall_ID))

    delete_Rules = []
    for rule in Firewall_Rules.keys():
      if Firewall_Rules[rule]['subnet_size'] is 32:
        delete_Rules.append(Firewall_Rules[rule]['rulenumber'])
    logging.info('Firewall rules scheduled for deletion = {}'.format(delete_Rules))
    for rule in delete_Rules:
      logging.debug('Deleting firewall rule {}'.format(rule))
      firewall_delete_rule(Firewall_ID, rule)
  
    logging.info('Creating new Firewall_Rules for {}'.format(Firewall_ID))
    try:
      from datetime import datetime
      timestamp = datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
      for port in TCP_PORTS:
        firewall_create_rule(Firewall_ID, 'tcp', Current_IP, 32, port, str('Created-{}'.format(timestamp)))
      for port in UDP_PORTS:
        firewall_create_rule(Firewall_ID, 'udp', Current_IP, 32, port, str('Created-{}'.format(timestamp)))
    except Exception as err:
      logging.exception('Could not create new firewall rules .. {}'.format(err))
      sys.exit(1)
  logging.info('** Finished script execution **')

if __name__ == '__main__':
    main()
