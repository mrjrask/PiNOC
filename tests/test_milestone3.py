import unittest
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory
from pinoc.database import Database, SCHEMA_VERSION
from pinoc.history import HistoryManager, storage_forecast
from pinoc.state import PiNOCState
from pinoc.web.app import create_app

class Milestone3Test(unittest.TestCase):
 def setUp(self):
  self.tmp=TemporaryDirectory(); self.db=Database(self.tmp.name+'/pinoc.db'); self.assertTrue(self.db.initialize(),self.db.error)
  self.history=HistoryManager(self.db,{'core_interval_seconds':60,'network_interval_seconds':60,'storage_interval_seconds':60,'thresholds':{'cpu_duration_seconds':0}})
 def tearDown(self): self.tmp.cleanup()
 def device(self,stamp,temp=75,online=True,ip='10.0.0.1'):
  return {'id':'pi','hostname':'pi','friendly_name':'Pi','online':online,'last_seen':stamp,'boot_time':'2026-01-01T00:00:00+00:00','uptime_seconds':100,'cpu':{'utilization_percent':95,'temperature_c':temp},'memory':{'percent':90},'hardware':{},'network':{'interface':'eth0','ip':ip,'rx_bytes':1,'tx_bytes':2},'storage':[{'mount_point':'/','total':1000,'used':850,'available':150,'percent':85}],'services':[]}
 def test_schema_reopen_sampling_and_alert_lifecycle(self):
  self.assertEqual(self.db.scalar('select version from schema_version'),SCHEMA_VERSION); self.assertTrue(Database(str(self.db.path)).initialize())
  now=datetime.now(timezone.utc); d=self.device(now.isoformat()); self.history._snapshot([d],now.isoformat()); self.history._snapshot([d],(now+timedelta(seconds=1)).isoformat())
  self.assertEqual(self.db.scalar('select count(*) from device_metrics'),1); self.assertEqual(self.db.scalar("select count(*) from alerts where resolved_at is null and alert_type='high_temperature'"),1)
  d=self.device((now+timedelta(seconds=61)).isoformat(),temp=20); d['cpu']['utilization_percent']=1;d['memory']['percent']=1;d['storage'][0]['percent']=1
  self.history._snapshot([d],d['last_seen']);self.assertEqual(self.db.scalar("select count(*) from alerts where alert_type='high_temperature' and resolved_at is not null"),1)
 def test_transitions_ack_and_mute(self):
  now=datetime.now(timezone.utc);a=self.device(now.isoformat());self.history._snapshot([a],now.isoformat());aid=self.db.scalar('select min(alert_id) from alerts');self.history.acknowledge(aid);self.assertEqual(self.db.scalar('select state from alerts where alert_id=?',(aid,)),'acknowledged');self.history.mute(aid,(now+timedelta(hours=1)).isoformat());self.assertEqual(self.db.scalar('select state from alerts where alert_id=?',(aid,)),'muted');self.history.unmute(aid)
  b=self.device((now+timedelta(minutes=2)).isoformat(),ip='10.0.0.2');b['uptime_seconds']=2;b['boot_time']='2026-01-02T00:00:00+00:00';self.history._snapshot([b],b['last_seen']);types={x['event_type'] for x in self.db.rows('select event_type from events')};self.assertIn('ip_changed',types);self.assertIn('device_rebooted',types)
 def test_expired_mute_reactivates_persistent_alert(self):
  now=datetime.now(timezone.utc);device=self.device(now.isoformat());self.history._snapshot([device],now.isoformat())
  aid=self.db.scalar("select min(alert_id) from alerts where alert_type='high_temperature'")
  self.history.mute(aid,(now-timedelta(minutes=1)).isoformat())
  self.history._snapshot([device],(now+timedelta(minutes=1)).isoformat())
  alert=self.db.rows('select state,muted_until from alerts where alert_id=?',(aid,))[0]
  self.assertEqual(alert['state'],'active');self.assertIsNone(alert['muted_until'])
 def test_restart_does_not_repeat_first_seen_event(self):
  now=datetime.now(timezone.utc);device=self.device(now.isoformat());self.history._snapshot([device],now.isoformat())
  restarted=HistoryManager(self.db,{'thresholds':{'cpu_duration_seconds':0}});restarted._snapshot([device],(now+timedelta(minutes=1)).isoformat())
  self.assertEqual(self.db.scalar("select count(*) from events where event_type='device_first_seen'"),1)
 def test_raw_metric_limit_keeps_newest_samples_in_order(self):
  now=datetime.now(timezone.utc);start=now-timedelta(days=4)
  with self.db.connect() as con:
   con.executemany('insert into device_metrics(timestamp,device_id,cpu_percent) values(?,?,?)',(((start+timedelta(minutes=i)).isoformat(),'pi',i) for i in range(5001)))
  response=create_app(PiNOCState(),history=self.history).test_client().get('/api/devices/pi/metrics?range=7d')
  core=response.get_json()['core'];self.assertEqual(len(core),5000);self.assertEqual(core[0]['cpu_percent'],1);self.assertEqual(core[-1]['cpu_percent'],5000)
 def test_mixed_metric_range_includes_complete_raw_segment(self):
  now=datetime.now(timezone.utc);start=now-timedelta(days=6)
  with self.db.connect() as con:
   con.executemany('insert into device_metrics(timestamp,device_id,cpu_percent) values(?,?,?)',(((start+timedelta(minutes=i)).isoformat(),'pi',i) for i in range(6001)))
  response=create_app(PiNOCState(),history=self.history).test_client().get('/api/devices/pi/metrics?range=30d')
  core=response.get_json()['core'];self.assertLessEqual(len(core),5000);self.assertEqual(core[0]['cpu_percent'],0);self.assertEqual(core[-1]['cpu_percent'],6000)
 def test_disabled_history_does_not_degrade_health(self):
  state=PiNOCState();state.publish([])
  disabled=HistoryManager(Database(self.tmp.name+'/disabled.db'),{'enabled':False})
  response=create_app(state,history=disabled).test_client().get('/health')
  self.assertEqual(response.status_code,200);self.assertEqual(response.get_json()['database']['status'],'disabled')
 def test_mute_endpoint_rejects_invalid_or_naive_deadline(self):
  now=datetime.now(timezone.utc);self.history._snapshot([self.device(now.isoformat())],now.isoformat())
  alert_id=self.db.scalar('select min(alert_id) from alerts');client=create_app(PiNOCState(),history=self.history).test_client()
  for deadline in ('not-a-date','2026-08-31T12:00:00'):
   response=client.post(f'/api/alerts/{alert_id}/mute',json={'muted_until':deadline})
   self.assertEqual(response.status_code,400)
  self.assertIsNone(self.db.scalar('select muted_until from alerts where alert_id=?',(alert_id,)))
 def test_maintenance_preserves_storage_and_network_aggregates(self):
  now=datetime.now(timezone.utc);old=now-timedelta(days=8);device=self.device(old.isoformat());device['network'].update(rx_rate=12,tx_rate=8,signal_dbm=-45,signal_quality_percent=90)
  self.history._snapshot([device],old.isoformat());self.history.maintenance(now)
  self.assertEqual(self.db.scalar('select count(*) from storage_metrics'),0);self.assertEqual(self.db.scalar('select count(*) from network_metrics'),0)
  self.assertEqual(self.db.scalar('select latest_used from storage_aggregates'),850);self.assertEqual(self.db.scalar('select avg_rx_rate from network_aggregates'),12)
 def test_forecast_states(self):
  now=datetime.now(timezone.utc);self.assertEqual(storage_forecast([])['status'],'insufficient')
  rows=[{'timestamp':(now+timedelta(days=i)).isoformat(),'used_bytes':100+i*10,'total_bytes':1000} for i in range(3)];self.assertEqual(storage_forecast(rows)['status'],'growing')
  for x in rows:x['used_bytes']=100
  self.assertEqual(storage_forecast(rows)['status'],'stable')
  for i,x in enumerate(rows):x['used_bytes']=100-i*10
  self.assertEqual(storage_forecast(rows)['status'],'decreasing')
