from app.application.services.headers_diff_service import HeadersDiffService
from app.domain.entities.header_snapshot import HeaderSnapshot
from app.domain.value_objects.change_type import ChangeType


def test_headers_removed():
    service = HeadersDiffService()
    prev = [
        HeaderSnapshot(
            url="https://api.com", headers={"Strict-Transport-Security": "max-age=31536000"}
        )
    ]
    curr = [HeaderSnapshot(url="https://api.com", headers={})]
    changes = service.compare(prev, curr)

    assert len(changes) == 1
    assert changes[0]["change_type"] == ChangeType.REMOVED
    assert changes[0]["details"]["header"] == "Strict-Transport-Security"


def test_headers_weakened():
    service = HeadersDiffService()
    prev = [
        HeaderSnapshot(
            url="https://api.com",
            headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"},
        )
    ]
    curr = [
        HeaderSnapshot(
            url="https://api.com", headers={"Strict-Transport-Security": "max-age=31536000"}
        )  # Perdió includeSubDomains
    ]
    changes = service.compare(prev, curr)

    assert len(changes) == 1
    assert changes[0]["change_type"] == ChangeType.WEAKENED
    assert changes[0]["details"]["header"] == "Strict-Transport-Security"
