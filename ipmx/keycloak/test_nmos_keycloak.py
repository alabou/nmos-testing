import importlib.util
from pathlib import Path


def _load_nmos_keycloak():
    path = Path(__file__).with_name("nmos_keycloak.py")
    spec = importlib.util.spec_from_file_location("nmos_keycloak", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kc = _load_nmos_keycloak()


def _subject(name: str, subject_type: str = "c"):
    return kc.SubjectGrants(
        subject_name=name,
        subject_type=subject_type,
        realm="TR-10-SEC",
    )


def _known_serials(*names: str) -> set[str]:
    return kc._controller_serials_from_subjects(
        [_subject(name) for name in names]
    )


def test_controller_prefix_client_is_controller() -> None:
    assert kc._is_controller_client("controller-SNX00001")
    assert kc._controller_serial("controller-SNX00001") == "SNX00001"


def test_controller_serials_come_from_explicit_controller_subjects() -> None:
    assert _known_serials("controller-SNX00001") == {"SNX00001"}


def test_certificate_style_client_is_controller_when_serial_is_known() -> None:
    name = "Example.Company.Device.Client.ABC.SNX00001.example.com"
    serials = _known_serials("controller-SNX00001")
    assert kc._is_controller_client(name, serials)
    assert kc._controller_serial(name, serials) == "SNX00001"


def test_certificate_style_serial_match_is_case_insensitive() -> None:
    name = "Example.Company.Device.Client.ABC.snx00001.example.com"
    serials = _known_serials("controller-SNX00001")
    assert kc._is_controller_client(name, serials)
    assert kc._controller_serial(name, serials) == "SNX00001"


def test_certificate_style_serial_does_not_depend_on_snx_prefix() -> None:
    name = "Example.Company.Device.Client.ABC.DEVICE0001.example.com"
    serials = _known_serials("controller-DEVICE0001")
    assert kc._is_controller_client(name, serials)
    assert kc._controller_serial(name, serials) == "DEVICE0001"


def test_certificate_style_client_without_known_serial_is_not_controller() -> None:
    name = "Example.Company.Device.Client.ABC.SNX00001.example.com"
    assert not kc._is_controller_client(name)
    assert not kc._is_controller_client(name, set())


def test_controller_serials_ignore_non_client_subjects() -> None:
    assert _known_serials("controller-SNX00001") == {"SNX00001"}
    subjects = [_subject("controller-SNX00001", subject_type="u")]
    assert kc._controller_serials_from_subjects(subjects) == set()


def test_client_without_serial_is_not_controller() -> None:
    assert not kc._is_controller_client("user1")


def test_certificate_style_redirect_uris_use_known_serial() -> None:
    serials = _known_serials("controller-SNX00001")
    serial = kc._controller_serial(
        "Example.Company.Device.Client.ABC.SNX00001.example.com",
        serials,
    )
    uris = kc._controller_redirect_uris(serial)
    assert "https://xyz-snx00001:5050/controller/oauth2/callback" in uris


def test_redirect_uris_are_exact_never_patterns() -> None:
    """IS-10 forbids pattern-matching on redirect URIs.

    "Redirect URIs MUST be complete (fully-qualified) and not use
    pattern-matching, as this makes them susceptible to Redirect URI
    Validation Attacks."

    These entries carried a trailing ``*`` until it was removed. Keycloak
    treats that as a prefix match, so a registration for
    ``.../callback*`` also authorises ``.../callback.attacker.example`` —
    an authorization code delivered somewhere the operator never approved.
    """
    uris = kc._controller_redirect_uris("SNX00001")
    assert uris, "expected at least one registered redirect URI"
    for uri in uris:
        assert "*" not in uri, f"{uri} uses pattern-matching"
        assert "?" not in uri and "#" not in uri, f"{uri} is not a bare URI"
        assert uri.startswith("https://"), f"{uri} is not TLS-protected"
        assert uri.endswith("/controller/oauth2/callback"), (
            f"{uri} is not the controller's callback path")


def test_redirect_uris_cover_what_the_controller_actually_builds() -> None:
    """The registered set must contain the URI the controller sends.

    ``nmos/controller/app.py`` builds it as ``{scheme}://{request.host}``
    plus the callback path, with the host lowercased by the HTTP layer. Now
    that matching is exact, a missing spelling is a failed login rather than
    something a wildcard quietly absorbed.
    """
    uris = kc._controller_redirect_uris("SNX00001")
    for host in ("xyz-snx00001:5050", "127.0.0.1:5050", "localhost:5050",
                 "xyz-snx00001"):
        expected = f"https://{host}/controller/oauth2/callback"
        assert expected in uris, f"{expected} is not registered"
