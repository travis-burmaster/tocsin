from tocsin.platforms import supported_capabilities


def test_linux_does_not_claim_macos_checks():
    assert 'brew' not in supported_capabilities('Linux')


def test_darwin_has_brew_capability():
    # Task 3 adds 'brew'; Task 4 adds 'project'; Task 6 adds 'files';
    # Task 7 adds 'posture' as its adapter lands.
    assert supported_capabilities('Darwin') == frozenset({'brew', 'project', 'files'})


def test_windows_has_no_capabilities():
    assert supported_capabilities('Windows') == frozenset()


def test_unknown_system_has_no_capabilities():
    assert supported_capabilities('Plan9') == frozenset()


def test_result_is_a_frozenset():
    assert isinstance(supported_capabilities('Darwin'), frozenset)
