from app.application.services.subdomains_diff_service import SubdomainsDiffService
from app.domain.entities.subdomain_asset import SubdomainAsset
from app.domain.value_objects.change_type import ChangeType


def test_subdomains_added():
    service = SubdomainsDiffService()
    prev = []
    curr = [
        SubdomainAsset(
            domain="empresa.com",
            subdomain="dev.empresa.com",
            ip="1.2.3.4",
            status="active",
            http_status=200,
            technology="nginx",
        )
    ]
    changes = service.compare(prev, curr)

    assert len(changes) == 1
    assert changes[0]["change_type"] == ChangeType.ADDED
    assert changes[0]["asset_identifier"] == "dev.empresa.com"


def test_subdomains_ip_changed():
    service = SubdomainsDiffService()
    prev = [
        SubdomainAsset(
            domain="empresa.com", subdomain="api.empresa.com", ip="1.2.3.4", status="active"
        )
    ]
    curr = [
        SubdomainAsset(
            domain="empresa.com", subdomain="api.empresa.com", ip="1.2.3.5", status="active"
        )
    ]
    changes = service.compare(prev, curr)

    assert len(changes) == 1
    assert changes[0]["change_type"] == ChangeType.MODIFIED
    assert changes[0]["details"]["previous_ip"] == "1.2.3.4"
    assert changes[0]["details"]["current_ip"] == "1.2.3.5"
