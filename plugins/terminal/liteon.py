from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import re

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils._text import to_bytes, to_text
from ansible.utils.display import Display
from ansible_collections.ansible.netcommon.plugins.plugin_utils.terminal_base import TerminalBase


display = Display()

class TerminalModule(TerminalBase):
    terminal_stdout_re = [re.compile(rb"(?:[>#]) ?(?:.*\x07)?$")]
    # terminal_stdout_re = [re.compile(rb"[\r\n]?[\w\+\-\.:\/\[\]]+(?:\([^\)]+\)){0,3}(?:[>#]) ?$")]

    terminal_stderr_re = [
        re.compile(rb"% ?Error"),
        # re.compile(rb"^% \w+", re.M),
        re.compile(rb"ERROR:", re.IGNORECASE),
        re.compile(rb"% ?Bad secret"),
        re.compile(rb"[\r\n%] Bad passwords"),
        re.compile(rb"invalid input", re.I),
        re.compile(rb"(?:incomplete|ambiguous) command", re.I),
        re.compile(rb"connection timed out", re.I),
        re.compile(rb"[^\r\n]+ not found"),
        re.compile(rb"'[^']' +returned error code: ?\d+"),
        re.compile(rb"Bad mask", re.I),
        re.compile(rb"% ?(\S+) ?overlaps with ?(\S+)", re.I),
        re.compile(rb"% ?(\S+) ?Error: ?[\s]+", re.I),
        re.compile(rb"% ?(\S+) ?Informational: ?[\s]+", re.I),
        re.compile(rb"Command authorization failed"),
        re.compile(rb"Command Rejected: ?[\s]+", re.I),
        re.compile(rb"% General session commands not allowed under the address family", re.I),
        re.compile(rb"% BGP: Error initializing topology", re.I),
        re.compile(rb"%SNMP agent not enabled", re.I),
        re.compile(rb"% Invalid", re.I), # Below are LiteON specific
        re.compile(rb"can not be", re.I),
    ]

    terminal_config_prompt = re.compile(r"^.+\(config(-.*)?\)#$")

    def on_become(self, passwd=None):
        if self._get_prompt().endswith(b"# "):
            return

        cmd = {"command": "enable"}
        if passwd:
            # Note: python-3.5 cannot combine u"" and r"" together.  Thus make
            # an r string and use to_text to ensure it's text on both py2 and py3.
            cmd["prompt"] = to_text(r"[\r\n]?(?:.*)?[Pp]assword: ?$", errors="surrogate_or_strict")
            cmd["answer"] = passwd
            cmd["prompt_retry_check"] = True
        try:
            self._exec_cli_command(to_bytes(json.dumps(cmd), errors="surrogate_or_strict"))
            prompt = self._get_prompt()
        except AnsibleConnectionFailure as e:
            prompt = self._get_prompt()
            raise AnsibleConnectionFailure(
                "failed to elevate privilege to enable mode, at prompt [%s] with error: %s"
                % (prompt, e.message),
            )

        if prompt is None or not prompt.endswith(b"# "):
            raise AnsibleConnectionFailure(
                "failed to elevate privilege to enable mode"
            )

    def on_unbecome(self):
        prompt = self._get_prompt()
        if prompt is None:
            # if prompt is None most likely the terminal is hung up at a prompt
            return

        if self._get_prompt().endswith(b"> "):
            return

        if b"(config" in prompt:
            self._exec_cli_command(b"exit")
            self._exec_cli_command(b"exit")

        elif prompt.endswith(b"# "):
            self._exec_cli_command(b"exit")
