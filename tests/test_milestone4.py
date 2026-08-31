import json
from datetime import datetime, timezone
from pinoc.collectors.fleet import integration_script, parse_integration_payloads
from pinoc.device_config import parse_device
from pinoc.integrations import active_integrations, IntegrationStatus, sanitize
from pinoc.integrations.adsb import parse_aircraft, parse_stats, compare
from pinoc.integrations.magicmirror import parse_pm2
from pinoc.integrations.pi_hotspot import parse_status as hotspot
from pinoc.integrations.raid import parse_mdstat
from pinoc.integrations.samba import parse_status
from pinoc.integrations.wireguard import parse_dump
from pinoc.integrations.disk_health import parse_nvme, parse_smart
from pinoc.integrations.packages import parse_apt
from pinoc.integrations.git import normalize
from pinoc.integrations.lan_inventory import enrich
from pinoc.models import DeviceState
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

def test_activation_override_and_status():
    assert active_integrations(['adsb_receiver'],{'adsb':False,'packages':True})==['packages']
    assert IntegrationStatus('x',health='bogus').to_dict()['health']=='unavailable'

def test_adsb_and_comparison():
    a=parse_aircraft({'aircraft':[{'hex':'abc','seen':1,'lat':1,'lon':2},{'hex':'old','seen':90}]})
    assert a['aircraft']==1 and a['aircraft_with_positions']==1
    assert parse_stats({'last1min':{'start':0,'end':60,'local':{'accepted':600}}})['messages_per_second']==10
    assert compare([{'device_id':'a','data':a},{'device_id':'b','data':{'aircraft_ids':['abc','def']}}])['aircraft_seen_by_all']==['abc']

def test_application_parsers():
    assert parse_pm2([{'name':'custom','pm2_env':{'status':'online'},'monit':{'memory':4}}],'custom')['process_state']=='online'
    assert hotspot({'clients':[],'internet':'online'},200,3)['client_count']==0
    assert parse_status({'sessions':{},'open_files':{}})['active_sessions']==0
    md='md0 : active raid1 sda1[0] sdb1[1]\n  100 blocks [2/1] [U_]\n'
    assert parse_mdstat(md)[0]['failed_devices']==1

def test_wireguard_and_secrets():
    text='wg0\tPUB\tPRIVATE\t51820\toff\nPEER\tpsk\thost:1\t10.0.0.0/24\t100\t12\t13\t25'
    assert parse_dump(text,{'PEER':'office'},required=['PEER'],now=114)[0]['peers'][0]['latest_handshake_seconds']==14
    assert 'private_key' not in sanitize({'private_key':'bad','data':1})

def test_disk_packages_git_inventory():
    assert parse_nvme({'critical_warning':1})['health']=='critical'
    assert parse_smart({'smart_status':{'passed':True}})['health']=='healthy'
    assert parse_apt('Inst one\nInst sec [1] (2 Debian-Security)',True)['security_updates']==1
    assert normalize('app','/x','branch=main\ncommit=abcdefghi\ndirty=1\nahead_behind=2 3')['behind']==3
    assert enrich([{'mac':'aa'}],[{'id':'pi','mac':'AA'}])[0]['managed']

def test_api_cached_and_sanitized():
    state=PiNOCState(); state.publish([DeviceState('a','a','A',integrations={'wireguard':{'health':'healthy','private_key':'NO'}})])
    c=create_app(state).test_client(); body=c.get('/api/devices/a/integrations').get_data(as_text=True)
    assert c.get('/api/adsb').status_code==200 and 'NO' not in body

def test_fleet_collects_and_parses_integration_payloads():
    device=parse_device({'hostname':'receiver','roles':['adsb_receiver'],'integrations':{
        'adsb':{'aircraft_url':'http://localhost/aircraft.json'}}},0)
    script=integration_script(device)
    assert 'curl -L --max-time 3' in script and 'aircraft.json' in script
    now=datetime.now(timezone.utc).isoformat()
    data={
        'INT_ADSB_AIRCRAFT':'__HTTP_META__=200 0.012\n'
            +json.dumps({'aircraft':[{'hex':'abc','seen':1,'lat':1,'lon':2}]}),
        'INT_ADSB_STATS':'__HTTP_META__=200 0.004\n'
            +json.dumps({'last1min':{'start':0,'end':10,'local':{'accepted':50}}}),
    }
    status=parse_integration_payloads(data,device,[],now,now,['adsb'])['adsb']
    assert status['available'] and status['health']=='healthy'
    assert status['data']['aircraft']==1 and status['data']['messages_per_second']==5
    assert status['data_source']=='dump1090 HTTP JSON'

def test_fleet_collects_non_service_integrations_and_repositories():
    device=parse_device({'hostname':'server','roles':['file_server'],'integrations':{'packages':True,'git':True},
                         'repositories':[{'name':'PiNOC','path':'/srv/pinoc'}]},0)
    script=integration_script(device)
    assert 'cat /proc/mdstat' in script and 'smartctl -a -j' in script
    assert 'apt-get -s' in script and 'git -C /srv/pinoc' in script
    now=datetime.now(timezone.utc).isoformat()
    data={'INT_RAID':'md0 : active raid1 sda[0] sdb[1]\n  10 blocks [2/2] [UU]',
          'INT_PACKAGES':'Inst one [1] (2 Debian-Security)\nREBOOT_REQUIRED=1',
          'INT_GIT_0':'name=PiNOC\npath=/srv/pinoc\nbranch=main\ncommit=abcdef123\ndirty=0'}
    statuses=parse_integration_payloads(data,device,[],now,now,['raid','packages','git'])
    assert statuses['raid']['available'] and statuses['raid']['data']['array_count']==1
    assert statuses['packages']['data']['updates_available']==1
    assert statuses['packages']['data']['reboot_required']
    assert statuses['git']['data']['repositories'][0]['branch']=='main'
