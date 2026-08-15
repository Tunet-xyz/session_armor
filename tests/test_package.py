import session_armor


def test_package_version_matches_release():
    assert session_armor.__version__ == "0.4.0"
