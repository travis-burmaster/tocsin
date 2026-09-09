"""Tests for the cross-cutting helpers in `tocsin.common`.

These three helpers were previously copied into the CLI, the adapters,
and the report module; a divergent copy of any of them is a correctness
bug, so this also pins that every module now uses the shared object.
"""

from __future__ import annotations

import re

from tocsin.adapters import clamav as clamav_module
from tocsin.adapters import curl as curl_module
from tocsin.adapters import osv as osv_module
from tocsin import cli as cli_module
from tocsin import common
from tocsin import report as report_module
from tocsin.platforms import macos as macos_module
from tocsin.platforms import macos_posture as posture_module


def test_runner_failure_map_covers_the_whole_failure_vocabulary():
    # 'missing' is deliberately absent: an absent engine is 'unavailable'
    # only in the adapters that probe for it, and each decides that for
    # itself. Everything else the runner can report has one meaning here.
    assert common.RUNNER_FAILURE_TO_COMPLETION == {
        'timeout': 'partial',
        'output-limit': 'partial',
        'cancelled': 'partial',
        'permission': 'error',
        'unavailable': 'unavailable',
    }


def test_unavailable_failure_maps_to_unavailable_not_error():
    # run_command returns 'unavailable' on a non-POSIX host (see
    # tests/test_runner.py::test_windows_returns_unavailable_without_starting_anything);
    # without this entry every adapter's `.get(failure, 'error')` would
    # report a Windows host as a failed check rather than an unsupported
    # one.
    assert common.RUNNER_FAILURE_TO_COMPLETION.get('unavailable') == 'unavailable'
    assert common.RUNNER_FAILURE_TO_COMPLETION.get('missing', 'error') == 'error'


def test_now_iso_is_a_utc_second_resolution_timestamp():
    assert re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', common.now_iso())


def test_escape_control_chars_escapes_controls_del_and_lone_surrogates():
    assert common.escape_control_chars('a\x1b[31mb\x07\x00\x7f') == 'a\\x1b[31mb\\x07\\x00\\x7f'
    # A non-UTF-8 filename byte, as os.fsdecode's surrogateescape handler
    # represents it, is rendered as the original byte value.
    assert common.escape_control_chars('bad\udcffname') == 'bad\\xffname'
    # Printable non-ASCII text is passed through unchanged.
    assert common.escape_control_chars('café ☕') == 'café ☕'


def test_every_module_uses_the_shared_helpers():
    assert cli_module.now_iso is common.now_iso
    for module in (clamav_module, curl_module, osv_module, macos_module, posture_module):
        assert module._now_iso is common.now_iso
    for module in (clamav_module, osv_module, macos_module):
        assert module._RUNNER_FAILURE_TO_COMPLETION is common.RUNNER_FAILURE_TO_COMPLETION
    for module in (report_module, clamav_module, posture_module):
        assert module._escape_control_chars is common.escape_control_chars
