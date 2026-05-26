from app.application.services.services_diff_service import ServicesDiffService
from app.domain.entities.exposed_service import ExposedService
from app.domain.value_objects.change_type import ChangeType


def test_services_diff_added():
    service = ServicesDiffService()
    prev = []
    curr = [
        ExposedService(
            host="api.com", ip="1.1.1.1", port=443, service="https", version="1.0", category="web"
        )
    ]
    changes = service.compare(prev, curr)

    assert len(changes) == 1
    assert changes[0]["change_type"] == ChangeType.ADDED
    assert changes[0]["details"]["current_service"] == "https"


def test_services_diff_version_changed():
    service = ServicesDiffService()
    prev = [
        ExposedService(
            host="api.com", ip="1.1.1.1", port=443, service="https", version="1.0", category="web"
        )
    ]
    curr = [
        ExposedService(
            host="api.com", ip="1.1.1.1", port=443, service="https", version="1.1", category="web"
        )
    ]
    changes = service.compare(prev, curr)

    assert len(changes) == 1
    assert changes[0]["change_type"] == ChangeType.MODIFIED
    assert changes[0]["details"]["previous_version"] == "1.0"
    assert changes[0]["details"]["current_version"] == "1.1"
