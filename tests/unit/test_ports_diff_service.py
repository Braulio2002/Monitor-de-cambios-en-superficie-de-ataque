from app.application.services.ports_diff_service import PortsDiffService
from app.domain.entities.exposed_port import ExposedPort
from app.domain.value_objects.change_type import ChangeType


def test_ports_diff_added():
    service = PortsDiffService()
    prev = []
    curr = [
        ExposedPort(
            target="api.com",
            ip="1.1.1.1",
            port=22,
            protocol="tcp",
            status="open",
            service="ssh",
            version="8.0",
        )
    ]
    changes = service.compare(prev, curr)

    assert len(changes) == 1
    assert changes[0]["change_type"] == ChangeType.ADDED
    assert changes[0]["asset_identifier"] == "api.com:22 (tcp)"
    assert changes[0]["details"]["current_service"] == "ssh"


def test_ports_diff_removed():
    service = PortsDiffService()
    prev = [
        ExposedPort(
            target="api.com",
            ip="1.1.1.1",
            port=22,
            protocol="tcp",
            status="open",
            service="ssh",
            version="8.0",
        )
    ]
    curr = []
    changes = service.compare(prev, curr)

    assert len(changes) == 1
    assert changes[0]["change_type"] == ChangeType.REMOVED
    assert changes[0]["details"]["previous_service"] == "ssh"


def test_ports_diff_modified():
    service = PortsDiffService()
    prev = [
        ExposedPort(
            target="api.com",
            ip="1.1.1.1",
            port=80,
            protocol="tcp",
            status="open",
            service="http",
            version="1.0",
        )
    ]
    curr = [
        ExposedPort(
            target="api.com",
            ip="1.1.1.1",
            port=80,
            protocol="tcp",
            status="open",
            service="http",
            version="2.0",
        )
    ]
    changes = service.compare(prev, curr)

    assert len(changes) == 1
    assert changes[0]["change_type"] == ChangeType.MODIFIED
    assert changes[0]["details"]["previous_version"] == "1.0"
    assert changes[0]["details"]["current_version"] == "2.0"
