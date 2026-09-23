from pinoc.actions import ActionDispatcher
from pinoc.database import Database
from pinoc.models import DeviceState
from pinoc.state import PiNOCState


def test_custom_integration_service_is_used_for_validation_and_execution(tmp_path):
    db = Database(str(tmp_path / "actions.sqlite"))
    assert db.initialize()
    state = PiNOCState()
    state.publish([DeviceState("pi", "pi", "Pi", online=True, address="host", collection_method="ssh",
                               manageable_services=["custom-mirror.service"],
                               integrations={"magicmirror": {"service": "custom-mirror.service"}})])
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
