import subprocess

from pinoc.actions import ActionDispatcher
from pinoc.collectors.fleet import FleetCollector
from pinoc.database import Database
from pinoc.device_config import parse_device
from pinoc.state import PiNOCState


def test_custom_integration_service_is_used_for_validation_and_execution(tmp_path):
    db = Database(str(tmp_path / "actions.sqlite"))
    assert db.initialize()
    state = PiNOCState()
    config = parse_device({"id": "pi", "hostname": "host",
                           "manageable_services": ["custom-mirror.service"],
                           "integrations": {"magicmirror": {
                               "enabled": True, "service": "custom-mirror.service"}}}, 0)
    output = ("__UPTIME__\n1 1\n__LOAD__\n0 0 0\n__CPU__\ncpu 1 0 1 8\n"
              "__MEM__\nMemTotal: 10 kB\nMemAvailable: 5 kB\n")
    snapshot = FleetCollector([config], runner=lambda cmd, **kwargs:
                              subprocess.CompletedProcess(cmd, 0, output, "")).collect_device(config)
    state.publish([snapshot])
    assert state.device("pi")["integrations"]["magicmirror"]["service"] == "custom-mirror.service"
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        class Result:
            returncode = 0
            stdout = ""
            stderr = ""
        return Result()

    dispatcher = ActionDispatcher(db, state, runner=runner)
    try:
        dispatcher.validate("magicmirror.restart", "pi")
        result = dispatcher._integration_service({"device_id": "pi", "action": "magicmirror.restart"}, 30)
        assert result["exit_code"] == 0
        assert calls[-1][-1] == "custom-mirror.service"
    finally:
        dispatcher.stop()
