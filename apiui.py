#!/usr/bin/env python3
"""

Steve Maher

Simple Textual-based API browser for Ansible AAP, GitLab, and any HTTP API.

Features:
- GET/POST/PUT/PATCH/DELETE
- Query params (key=value per line)
- Headers (key=value per line), auto adds Bearer token if provided
- JSON body or application/x-www-form-urlencoded
- TLS verify toggle, timeout
- Pretty response: status, headers, syntax-highlighted body

Run:
  python apiui.py
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urljoin
from typing import Dict, Tuple

import httpx
from rich.syntax import Syntax
from rich.pretty import Pretty

from textual.app import App, ComposeResult
from textual.reactive import var
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import (
    Header,
    Footer,
    Input,
    Button,
    Label,
    Select,
    Checkbox,
    Static,
    Tabs,
    TabPane,
    TabbedContent,
    RadioSet,
    RadioButton,
    TextArea,
)

# -------- Helpers --------

def parse_kv_multiline(text: str) -> Dict[str, object]:
    """
    Parse lines of 'key=value' into a dict.
    Supports JSON values with @json: prefix, e.g. value=@json:["a",1]
    Blank lines and lines starting with # are ignored.
    """
    result: Dict[str, object] = {}
    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Line {i}: expected key=value, got: {raw_line!r}")
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if v.startswith("@json:"):
            try:
                v = json.loads(v[len("@json:"):])
            except json.JSONDecodeError as e:
                raise ValueError(f"Line {i}: invalid JSON for {k}: {e}")
        result[k] = v
    return result


def body_from_mode(mode: str, json_text: str, form_text: str) -> Tuple[Dict | None, Dict | None, str]:
    """
    Returns (json_body, form_body, content_type)
    """
    if mode == "json":
        if not json_text.strip():
            return None, None, "application/json"
        try:
            return json.loads(json_text), None, "application/json"
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON body is not valid JSON:\n{e}")
    else:
        form = parse_kv_multiline(form_text)
        return None, form, "application/x-www-form-urlencoded"


def guess_syntax_from_ct(content_type: str, text: str) -> str:
    ct = (content_type or "").lower()
    if "json" in ct:
        return "json"
    if "yaml" in ct or "yml" in ct:
        return "yaml"
    if "xml" in ct:
        return "xml"
    if "html" in ct:
        return "html"
    # Fallback heuristic
    t = text.strip()
    if t.startswith("{") or t.startswith("["):
        return "json"
    if ":" in t and "\n" in t:
        return "yaml"
    return "markdown"


# -------- App --------

class ApiBrowserApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    #topbar {
        height: 3;
    }
    #main {
        height: 1fr;
    }
    #left, #right {
        width: 1fr;
        height: 1fr;
    }
    .card {
        border: solid $primary 1px;
        padding: 1;
        border-title-color: $text 50%;
        border-round: true;
    }
    Label {
        width: 20;
        color: $text 80%;
    }
    Input, TextArea, Select {
        width: 1fr;
    }
    TextArea {
        height: 8;
    }
    #status {
        height: 3;
    }
    #headers_view, #body_view {
        height: 1fr;
    }
    #send_row {
        height: 3;
        align-horizontal: right;
        content-align: right middle;
    }
    #token {
        password: true;
    }
    """

    BINDINGS = [
        ("ctrl+s", "send", "Send"),
        ("f2", "toggle_verify", "Toggle Verify TLS"),
        ("f5", "clear_response", "Clear Response"),
        ("ctrl+q", "quit", "Quit"),
    ]

    # reactive fields for status
    sending: var[bool] = var(False)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="topbar"):
            with Horizontal():
                yield Label("Base URL")
                self.base = Input(placeholder="https://aap.example.com/", id="base")
                yield self.base
                yield Label("Endpoint")
                self.endpoint = Input(value="/api/v2/ping/", id="endpoint")
                yield self.endpoint
                yield Label("Method")
                self.method = Select(
                    options=[(m, m) for m in ["GET", "POST", "PUT", "PATCH", "DELETE"]],
                    value="GET",
                    id="method",
                )
                yield self.method
                self.send_btn = Button("Send (Ctrl+S)", id="send")
                yield self.send_btn

        with Horizontal(id="main"):
            # LEFT: request
            with Vertical(id="left"):
                with Container(classes="card", id="req_core"):
                    with Horizontal():
                        yield Label("Bearer Token")
                        self.token = Input(placeholder="Optional", id="token")
                        yield self.token
                        self.verify = Checkbox(label="Verify TLS", value=True, id="verify")
                        yield self.verify
                        yield Label("Timeout (s)")
                        self.timeout = Input(value="30", id="timeout")
                        yield self.timeout

                with Container(classes="card", id="req_params"):
                    yield Label("Query Params (key=value per line)")
                    self.params = TextArea(code=False, id="params")
                    yield self.params

                with Container(classes="card", id="req_headers"):
                    yield Label("Headers (key=value per line)")
                    self.headers = TextArea(code=False, id="headers")
                    yield self.headers

                with Container(classes="card", id="req_body"):
                    with Horizontal():
                        yield Label("Body Mode")
                        self.mode = RadioSet(id="mode")
                        self.mode.can_focus = True
                        self.mode.add_radio_button(RadioButton("JSON", value=True, id="mode_json"))
                        self.mode.add_radio_button(RadioButton("Form", id="mode_form"))
                        yield self.mode
                    self.body_tabs = TabbedContent(
                        TabPane(TextArea(id="json_area", language="json", placeholder='{"example": "value"}'), id="tab_json", title="JSON"),
                        TabPane(TextArea(id="form_area", placeholder="key=value\nanother=123"), id="tab_form", title="Form"),
                        id="body_tabs",
                    )
                    yield self.body_tabs

                with Container(id="send_row"):
                    yield Button("Send (Ctrl+S)", variant="primary", id="send_bottom")

            # RIGHT: response
            with Vertical(id="right"):
                with Container(classes="card"):
                    self.status = Static("[i]Ready[/i]", id="status")
                    yield self.status
                with Container(classes="card"):
                    yield Label("Response Headers")
                    self.headers_view = Static("", id="headers_view")
                    yield self.headers_view
                with Container(classes="card"):
                    yield Label("Response Body")
                    self.body_view = Static("", id="body_view")
                    yield self.body_view

        yield Footer()

    # ------ events & actions ------

    def on_mount(self) -> None:
        # Default JSON tab selected
        self.body_tabs.active = "tab_json"
        self.query_one("#mode_json", RadioButton).value = True

        # A few helpful defaults for AAP / GitLab demos
        self.base.value = "https://gitlab.com/"
        self.endpoint.value = "/api/v4/projects"
        self.params.value = "membership=true"
        self.headers.value = "# Example header line\n# PRIVATE-TOKEN=xxxxx"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id in {"send", "send_bottom"}:
            self.action_send()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id == "mode":
            if event.pressed.id == "mode_json":
                self.body_tabs.active = "tab_json"
            else:
                self.body_tabs.active = "tab_form"

    def action_toggle_verify(self) -> None:
        self.verify.value = not self.verify.value

    def action_clear_response(self) -> None:
        self.status.update("[i]Cleared[/i]")
        self.headers_view.update("")
        self.body_view.update("")

    async def _send_request(self) -> None:
        if self.sending:
            return
        self.sending = True
        self.status.update("[yellow]Sending...[/yellow]")

        # Gather inputs
        base = self.base.value.strip()
        endpoint = self.endpoint.value.strip() or "/"
        method = (self.method.value or "GET").upper()
        token = self.token.value.strip()
        verify = bool(self.verify.value)
        try:
            timeout_val = float(self.timeout.value.strip() or "30")
        except ValueError:
            timeout_val = 30.0

        # Build URL
        if not base:
            self.status.update("[red]Base URL is required[/red]")
            self.sending = False
            return
        url = urljoin(base if base.endswith("/") else f"{base}/", endpoint.lstrip("/"))

        # Headers/params
        try:
            headers = parse_kv_multiline(self.headers.value)
        except Exception as e:
            self.status.update(f"[red]Header parse error:[/red] {e}")
            self.sending = False
            return
        try:
            params = parse_kv_multiline(self.params.value)
        except Exception as e:
            self.status.update(f"[red]Param parse error:[/red] {e}")
            self.sending = False
            return

        # Token -> Authorization unless user already set it
        if token and "Authorization" not in {k.title(): v for k, v in headers.items()}:
            headers["Authorization"] = f"Bearer {token}"

        # Body
        mode = "json" if self.body_tabs.active == "tab_json" else "form"
        json_text = self.query_one("#json_area", TextArea).text
        form_text = self.query_one("#form_area", TextArea).text
        try:
            json_body, form_body, content_type = body_from_mode(mode, json_text, form_text)
        except Exception as e:
            self.status.update(f"[red]{e}[/red]")
            self.sending = False
            return
        headers.setdefault("Content-Type", content_type)

        # Send via httpx
        try:
            async with httpx.AsyncClient(timeout=timeout_val, verify=verify, follow_redirects=True) as client:
                resp = await client.request(
                    method,
                    url,
                    headers=headers,
                    params=params or None,
                    json=json_body,
                    data=form_body,
                )
        except httpx.HTTPError as e:
            self.status.update(f"[red]Request error:[/red] {e}")
            self.sending = False
            return

        # Update UI with response
        status_color = "green" if 200 <= resp.status_code < 300 else ("yellow" if resp.status_code < 400 else "red")
        self.status.update(f"[{status_color}]{resp.status_code} {resp.reason_phrase}[/]  {resp.url}")

        # Headers
        hdr_lines = "\n".join(f"[b]{k}[/b]: {v}" for k, v in resp.headers.items())
        self.headers_view.update(hdr_lines)

        # Body (pretty)
        ctype = resp.headers.get("Content-Type", "")
        if "application/json" in (ctype or "").lower():
            try:
                data = resp.json()
                renderable = Pretty(data, expand_all=False)
                self.body_view.update(renderable)
            except Exception:
                self.body_view.update(Syntax(resp.text, "json", word_wrap=True))
        elif "text/" in ctype or ctype == "":
            lang = guess_syntax_from_ct(ctype, resp.text)
            self.body_view.update(Syntax(resp.text, lang, word_wrap=True))
        else:
            self.body_view.update(f"[dim]Binary content ({len(resp.content)} bytes)[/dim]")

        self.sending = False

    def action_send(self) -> None:
        self.call_later(self._send_request())

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        # If user hits Enter in any of the top inputs, send
        if event.input.id in {"base", "endpoint"}:
            await self._send_request()


if __name__ == "__main__":
    ApiBrowserApp().run()
