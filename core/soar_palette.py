"""The SOAR builder's node palette.

187 lines of static catalogue - what a playbook node can be, which fields each
kind takes, and which of them this deployment has enabled. It described the
UI, sat in the middle of app.py, and changed only when a new node type was
added.

`is_soar_enabled` is injected rather than imported: the palette is data, and
this keeps it out of app.py's import graph so it can be rendered in a test
without a server or a database.
"""

from __future__ import annotations

_soar_enabled = lambda: True         # replaced by set_defaults()


def set_defaults(*, soar_enabled):
    global _soar_enabled
    _soar_enabled = soar_enabled


def _palette_actions_enabled():
    return bool(_soar_enabled())

def _node_schema(type_name, label, category, inputs=None, outputs=None, config_schema=None, disabled=False, help_text=""):
    return {
        "type": type_name,
        "label": label,
        "category": category,
        "disabled": bool(disabled),
        "inputs": inputs or [{"name": "in", "accept": "*"}],
        "outputs": outputs or [{"name": "out"}],
        "config_schema": config_schema or {},
        "help": help_text,
    }

def _build_node_palette():
    actions_enabled = _palette_actions_enabled()

    nodes = []

    nodes.append(_node_schema(
        "trigger",
        "Trigger (Generic)",
        "trigger",
        inputs=[],
        outputs=[{"name": "out"}],
        config_schema={
            "triggerType": {"type": "string", "placeholder": "manual"},
            "schedule": {"type": "string", "placeholder": ""},
            "webhook": {"type": "string", "placeholder": ""},
            "conditions": {"type": "array", "default": []}
        },
        help_text="Generic trigger placeholder. Use triggerType to specify the real trigger."
    ))
    nodes.append(_node_schema(
        "action",
        "Action (Generic)",
        "action",
        config_schema={
            "actionType": {"type": "string", "placeholder": "http_request"},
            "target": {"type": "string", "placeholder": ""},
            "comment": {"type": "string", "placeholder": ""},
            "ttl": {"type": "number", "default": 0},
            "params": {"type": "string", "placeholder": "{}"}
        },
        disabled=not actions_enabled,
        help_text="Generic action placeholder. actionType determines the SOAR action or HTTP request."
    ))

    nodes.append(_node_schema(
        "trigger.events_alert",
        "When Events Alert Arrives",
        "trigger",
        inputs=[],
        outputs=[{"name": "on_alert"}],
        config_schema={
            "source": {"type": "string", "required": False, "title": "Source contains"},
            "min_severity": {"type": "string", "enum": ["LOW","MEDIUM","HIGH","CRITICAL"], "default": "MEDIUM"},
        },
        help_text="Fires when a new row lands in events_alert (filtered in the UI simulation).",
    ))

    nodes.append(_node_schema(
        "trigger.time",
        "Cron/Time Trigger",
        "trigger",
        inputs=[],
        outputs=[{"name": "tick"}],
        config_schema={"cron": {"type": "string", "placeholder": "*/5 * * * *"}},
        help_text="Time-based trigger (UI simulation only).",
    ))

    nodes.append(_node_schema(
        "condition.severity_at_least",
        "Severity ≥",
        "condition",
        config_schema={"threshold": {"type": "string", "enum": ["LOW","MEDIUM","HIGH","CRITICAL"], "default": "HIGH"}},
        help_text="Compares context.severity against a threshold.",
    ))
    nodes.append(_node_schema(
        "condition.text_match",
        "Text contains",
        "condition",
        config_schema={"field": {"type": "string", "default": "message"}, "needle": {"type": "string"}},
        help_text="Searches for a needle inside context[field].",
    ))

    nodes.append(_node_schema(
        "action.soar.block_ip",
        "SOAR: Block IP",
        "action",
        config_schema={"ip": {"type": "string", "placeholder": "{{event.ip}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> block_ip.",
    ))
    nodes.append(_node_schema(
        "action.soar.disable_user",
        "SOAR: Disable User",
        "action",
        config_schema={"username": {"type": "string", "placeholder": "{{event.username}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> disable_user.",
    ))

    nodes.append(_node_schema(
        "action.soar.unblock_ip",
        "SOAR: Unblock IP",
        "action",
        config_schema={"ip": {"type": "string", "placeholder": "{{event.ip}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> unblock_ip."
    ))
    nodes.append(_node_schema(
        "action.soar.enable_user",
        "SOAR: Enable User",
        "action",
        config_schema={"username": {"type": "string", "placeholder": "{{event.username}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> enable_user."
    ))
    nodes.append(_node_schema(
        "action.soar.kill_process",
        "SOAR: Kill Process",
        "action",
        config_schema={"pid": {"type": "string", "placeholder": "{{event.pid}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> kill_process."
    ))
    nodes.append(_node_schema(
        "action.soar.restart_service",
        "SOAR: Restart Service",
        "action",
        config_schema={"service": {"type": "string", "placeholder": "{{event.service}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> restart_service."
    ))
    nodes.append(_node_schema(
        "action.soar.lock_machine",
        "SOAR: Lock Machine",
        "action",
        config_schema={"machine": {"type": "string", "placeholder": "{{event.host}}"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> lock_machine."
    ))
    nodes.append(_node_schema(
        "action.soar.quarantine_file",
        "SOAR: Quarantine File",
        "action",
        config_schema={"filepath": {"type": "string", "placeholder": "/path/to/file"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> quarantine_file."
    ))
    nodes.append(_node_schema(
        "action.soar.tail_log",
        "SOAR: Tail Log",
        "action",
        config_schema={"logfile": {"type": "string", "placeholder": "/var/log/syslog"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> tail_log."
    ))
    nodes.append(_node_schema(
        "action.soar.run_cmd",
        "SOAR: Run Command",
        "action",
        config_schema={"command": {"type": "string", "placeholder": "uptime"}},
        disabled=not actions_enabled,
        help_text="Agent SOAR /soar/execute -> run_cmd."
    ))

    nodes.append(_node_schema(
        "notify.email",
        "Send Email (template)",
        "notify",
        config_schema={
            "template_name": {"type": "string", "placeholder": "Critical Alerts - Agent: {{agent}}"},
            "context_json": {"type": "string", "placeholder": "{\"agent\":\"{{agent}}\",\"body\":\"...\"}"}
        },
        help_text="Sends mail using a template from userdb.email_templates.",
    ))

    nodes.append(_node_schema(
        "util.delay",
        "Delay",
        "util",
        config_schema={"ms": {"type": "number", "default": 1000}},
        help_text="Pauses the flow for N ms (capped at 5s during execution).",
    ))

    return {"nodes": nodes, "soar_enabled": actions_enabled}
