# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
The component library and the attribute schema.

One source of truth, in Python, serialised into the page as JSON. The palette,
the properties form, the overlay writer and the rule engine all read the same
definitions, so adding a component type or an attribute is a single edit.

Why attributes matter
---------------------
A properties panel that only records prose is a form. Every attribute here is
addressable by a rule as `attr.<key>`, so answering "does this sanitise input?"
with *no* produces a finding with the answer as its evidence. That is the same
bargain the scanner makes with a manifest: a claim in, a citation out.

Attributes are three-state on purpose. `null` means nobody has said, and that is
different from `false`. Unanswered questions are reported as coverage gaps, not
silently treated as safe — the whole reason the old pipeline produced 2,337
"threats" was that it assumed an answer for every question it never asked.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Icons. A small reusable set; components refer to them by name so the page
# ships one copy of each path rather than one per component.
# ---------------------------------------------------------------------------

ICONS: Dict[str, str] = {
    "box":      "M3 7l7-4 7 4v6l-7 4-7-4z",
    "globe":    "M10 2a8 8 0 100 16 8 8 0 000-16zM2 10h16M10 2c2.5 2.5 2.5 13 0 16"
                "M10 2C7.5 4.5 7.5 15.5 10 18",
    "gateway":  "M3 6h14M3 14h14M7 6v8M13 6v8",
    "cube":     "M10 2l7 4v8l-7 4-7-4V6z M10 10l7-4M10 10v8M10 10L3 6",
    "bolt":     "M11 2L4 11h5l-1 7 7-9h-5z",
    "gear":     "M10 6.5a3.5 3.5 0 100 7 3.5 3.5 0 000-7zM10 1v3M10 16v3M1 10h3"
                "M16 10h3M3.6 3.6l2.1 2.1M14.3 14.3l2.1 2.1M16.4 3.6l-2.1 2.1"
                "M5.7 14.3l-2.1 2.1",
    "db":       "M10 3c3.9 0 7 1.1 7 2.5S13.9 8 10 8 3 6.9 3 5.5 6.1 3 10 3z"
                "M3 5.5v9C3 15.9 6.1 17 10 17s7-1.1 7-2.5v-9",
    "cache":    "M3 5h14v10H3z M3 9h14M7 5v10M13 5v10",
    "bucket":   "M3 5h14l-1.5 12h-11z M3 5l1-2h12l1 2",
    "search":   "M9 3a6 6 0 104.2 10.2L17 17M9 3a6 6 0 010 12",
    "folder":   "M2 5h6l2 2h8v9H2z",
    "queue":    "M2 6h16v3H2z M2 11h16v3H2z",
    "stream":   "M2 5c4 0 4 5 8 5s4-5 8-5M2 12c4 0 4 3 8 3s4-3 8-3",
    "bell":     "M10 2a5 5 0 00-5 5v4l-2 3h14l-2-3V7a5 5 0 00-5-5zM8 17h4",
    "hook":     "M13 3v6a4 4 0 01-8 0V7M13 3l-2 2M13 3l2 2",
    "balance":  "M10 3v14M4 7h12M6 7l-3 5h6zM14 7l-3 5h6z",
    "shield":   "M10 2l7 3v5c0 4-3 7-7 8-4-1-7-4-7-8V5z",
    "lock":     "M5 9h10v8H5z M7 9V6a3 3 0 016 0v3",
    "key":      "M12 3a4 4 0 00-3.5 6L3 14.5V17h2.5l.5-2h2v-2h2l1-1A4 4 0 1012 3z",
    "cert":     "M4 3h12v10H4z M7 16l3-2 3 2v-3H7z",
    "eye":      "M1 10s3.5-5 9-5 9 5 9 5-3.5 5-9 5-9-5-9-5z M10 8a2 2 0 100 4 2 2 0 000-4z",
    "wall":     "M2 4h16v12H2z M2 8h16M2 12h16M6 4v4M14 4v4M10 8v4M6 12v4M14 12v4",
    "mesh":     "M10 2l6 4v8l-6 4-6-4V6z M10 2v16M4 6l12 8M16 6L4 14",
    "dns":      "M10 2v16M2 10h16M5 5l10 10M15 5L5 15",
    "vpn":      "M10 2l6 3v5c0 4-2.5 6.5-6 8-3.5-1.5-6-4-6-8V5z M7 10l2 2 4-4",
    "phone":    "M6 2h8v16H6z M9 15h2",
    "monitor":  "M2 4h16v9H2z M7 17h6M10 13v4",
    "terminal": "M2 4h16v12H2z M5 8l3 2-3 2M10 12h5",
    "chip":     "M6 6h8v8H6z M8 2v4M12 2v4M8 14v4M12 14v4M2 8h4M2 12h4M14 8h4M14 12h4",
    "cloud":    "M6 15a4 4 0 010-8 5 5 0 019.5 1.5A3.5 3.5 0 0115 15z",
    "clock":    "M10 2a8 8 0 100 16 8 8 0 000-16z M10 6v4l3 2",
    "user":     "M10 3a3.5 3.5 0 100 7 3.5 3.5 0 000-7z M3 18c0-4 3.5-6 7-6s7 2 7 6",
    "card":     "M2 5h16v10H2z M2 9h16M5 12h3",
    "mail":     "M2 5h16v10H2z M2 5l8 6 8-6",
    "plug":     "M7 2v5M13 2v5M5 7h10v3a5 5 0 01-10 0z M10 15v3",
    "text":     "M4 4h12M10 4v12M7 16h6",
    "boundary": "M3 3h14v14H3z",
}

# ---------------------------------------------------------------------------
# Components. `element` is the DFD classification the analysis uses; `label` and
# `category` are what the human sees.
# ---------------------------------------------------------------------------

def _c(cid: str, label: str, category: str, element: str, icon: str,
       tech: Optional[List[str]] = None, zone: str = "internal",
       data: Optional[List[str]] = None,
       attrs: Optional[Dict[str, Any]] = None,
       hint: str = "") -> Dict[str, Any]:
    return {"id": cid, "label": label, "category": category, "element": element,
            "icon": icon, "tech": tech or [], "zone": zone, "data": data or [],
            "attrs": attrs or {}, "hint": hint}


COMPONENTS: List[Dict[str, Any]] = [
    # -- Generic ------------------------------------------------------------
    _c("process", "Process", "Generic", "process", "cube",
       hint="Anything that runs code."),
    _c("data_store", "Data store", "Generic", "data_store", "db",
       hint="Anything that holds state."),
    _c("external_entity", "External entity", "Generic", "external_entity", "user",
       zone="external", hint="Something you do not control."),

    # -- Clients ------------------------------------------------------------
    _c("browser", "Browser", "Clients", "external_entity", "globe", ["javascript"],
       zone="external", attrs={"authenticates_itself": False},
       hint="Untrusted by definition: the user controls it."),
    _c("mobile_app", "Mobile app", "Clients", "external_entity", "phone",
       ["ios", "android"], zone="external",
       hint="Shipped to a device you do not control; assume it is reverse-engineered."),
    _c("desktop_app", "Desktop app", "Clients", "external_entity", "monitor",
       zone="external"),
    _c("cli_tool", "CLI tool", "Clients", "external_entity", "terminal",
       zone="external"),
    _c("iot_device", "IoT device", "Clients", "external_entity", "chip",
       zone="external", hint="Rarely patched, often physically reachable."),
    _c("human_actor", "Human actor", "Clients", "external_entity", "user",
       zone="external", hint="An operator, admin or customer."),

    # -- Services -----------------------------------------------------------
    _c("web_server", "Web server", "Services", "process", "globe",
       ["nginx", "apache"], zone="dmz",
       attrs={"accepts_input_from": "any_remote"}),
    _c("api_gateway", "API gateway", "Services", "process", "gateway",
       ["kong", "apigee"], zone="dmz",
       attrs={"accepts_input_from": "any_remote", "implements_authn": True}),
    _c("api_endpoint", "API endpoint", "Services", "process", "plug",
       attrs={"accepts_input_from": "any_remote"}),
    _c("microservice", "Microservice", "Services", "process", "cube"),
    _c("serverless_fn", "Serverless function", "Services", "process", "bolt",
       ["lambda", "cloud-functions"]),
    _c("background_worker", "Background worker", "Services", "process", "gear",
       hint="Often runs with wider privilege than the API that feeds it."),
    _c("batch_job", "Batch job", "Services", "process", "clock"),
    _c("graphql_api", "GraphQL API", "Services", "process", "mesh",
       attrs={"accepts_input_from": "any_remote"},
       hint="One endpoint, arbitrary query shape — authorisation is per-field."),
    _c("grpc_service", "gRPC service", "Services", "process", "plug"),
    _c("admin_console", "Admin console", "Services", "process", "monitor",
       attrs={"running_as": "administrator"},
       hint="High privilege by design; the first thing an attacker looks for."),

    # -- Databases ----------------------------------------------------------
    _c("sql_db", "SQL database", "Databases", "data_store", "db",
       ["postgres", "mysql"], data=["pii"],
       attrs={"store_type": "sql", "write_access": True}),
    _c("nosql_db", "NoSQL database", "Databases", "data_store", "db",
       ["mongodb", "dynamodb"], data=["pii"], attrs={"store_type": "nosql"}),
    _c("cache", "Cache", "Databases", "data_store", "cache", ["redis"],
       attrs={"store_type": "cache"},
       hint="Frequently holds session tokens and is frequently unauthenticated."),
    _c("object_storage", "Object storage", "Databases", "data_store", "bucket",
       ["s3", "blob"], attrs={"store_type": "blob"}),
    _c("data_warehouse", "Data warehouse", "Databases", "data_store", "db",
       ["snowflake", "bigquery"], data=["pii"],
       hint="Aggregated data: the blast radius is the whole business."),
    _c("search_index", "Search index", "Databases", "data_store", "search",
       ["elasticsearch"]),
    _c("file_share", "File share", "Databases", "data_store", "folder",
       ["smb", "nfs"]),
    _c("log_store", "Log store", "Databases", "data_store", "folder",
       attrs={"stores_log_data": True},
       hint="Logs leak secrets more often than databases do."),

    # -- Messaging ----------------------------------------------------------
    _c("message_queue", "Message queue", "Messaging", "data_store", "queue",
       ["rabbitmq", "sqs"]),
    _c("event_bus", "Event bus", "Messaging", "data_store", "stream",
       ["kafka", "eventbridge"]),
    _c("stream", "Stream", "Messaging", "data_store", "stream", ["kinesis"]),
    _c("webhook", "Webhook", "Messaging", "process", "hook",
       attrs={"accepts_input_from": "any_remote"},
       hint="An inbound endpoint anyone can call unless it verifies signatures."),
    _c("notification_svc", "Notification service", "Messaging", "process", "bell"),

    # -- Infrastructure -----------------------------------------------------
    _c("load_balancer", "Load balancer", "Infrastructure", "process", "balance",
       zone="dmz"),
    _c("reverse_proxy", "Reverse proxy", "Infrastructure", "process", "gateway",
       ["nginx", "envoy"], zone="dmz"),
    _c("cdn", "CDN", "Infrastructure", "process", "cloud", zone="external"),
    _c("container_runtime", "Container runtime", "Infrastructure", "process", "box",
       ["docker", "containerd"]),
    _c("k8s_cluster", "Kubernetes cluster", "Infrastructure", "process", "mesh",
       ["kubernetes"]),
    _c("virtual_machine", "Virtual machine", "Infrastructure", "process", "monitor"),
    _c("scheduler", "Scheduler", "Infrastructure", "process", "clock", ["cron"]),

    # -- Security -----------------------------------------------------------
    _c("identity_provider", "Identity provider", "Security", "process", "user",
       ["oidc", "saml"], attrs={"implements_authn": True},
       hint="Compromise here is compromise everywhere."),
    _c("auth_service", "Auth service", "Security", "process", "lock",
       attrs={"implements_authn": True, "implements_authz": True}),
    _c("secrets_manager", "Secrets manager", "Security", "data_store", "key",
       ["vault"], data=["secret"], zone="restricted",
       attrs={"stores_credentials": True, "encrypted": True}),
    _c("kms", "KMS / HSM", "Security", "data_store", "key", data=["secret"],
       zone="restricted", attrs={"stores_credentials": True, "encrypted": True}),
    _c("waf", "WAF", "Security", "process", "shield", zone="dmz"),
    _c("siem", "SIEM", "Security", "data_store", "eye", data=["pii"],
       attrs={"stores_log_data": True}),
    _c("cert_authority", "Certificate authority", "Security", "process", "cert",
       zone="restricted"),

    # -- Networking ---------------------------------------------------------
    _c("vpn_gateway", "VPN gateway", "Networking", "process", "vpn", zone="dmz",
       attrs={"accepts_input_from": "any_remote"},
       hint="The perimeter's front door; internet-facing and highly privileged."),
    _c("firewall", "Firewall", "Networking", "process", "wall", zone="dmz"),
    _c("service_mesh", "Service mesh", "Networking", "process", "mesh",
       ["istio", "linkerd"]),
    _c("dns", "DNS", "Networking", "process", "dns"),
    _c("private_link", "Private link", "Networking", "process", "plug"),

    # -- External -----------------------------------------------------------
    _c("saas", "Third-party SaaS", "External", "external_entity", "cloud",
       zone="partner", hint="Outside your control and outside your logging."),
    _c("payment_provider", "Payment provider", "External", "external_entity", "card",
       zone="partner", data=["pci"]),
    _c("email_provider", "Email provider", "External", "external_entity", "mail",
       zone="partner"),
    _c("partner_system", "Partner system", "External", "external_entity", "box",
       zone="partner"),
    _c("internet", "Internet", "External", "external_entity", "globe",
       zone="external", hint="The anonymous attacker."),
]

CATEGORIES: List[str] = ["Generic", "Clients", "Services", "Databases",
                         "Messaging", "Infrastructure", "Security",
                         "Networking", "External"]

BY_ID: Dict[str, Dict[str, Any]] = {c["id"]: c for c in COMPONENTS}


# ---------------------------------------------------------------------------
# Attributes.
#
# `rule` on an attribute names the finding it can raise, so the properties form
# can tell the user which answers matter and the docs stay honest about which
# questions are decorative (none of them are).
# ---------------------------------------------------------------------------

def _a(key: str, label: str, kind: str, values: Optional[List[str]] = None,
       rule: str = "", hint: str = "") -> Dict[str, Any]:
    return {"key": key, "label": label, "kind": kind, "values": values or [],
            "rule": rule, "hint": hint}


UNIVERSAL: List[Dict[str, Any]] = [
    _a("out_of_scope", "Out of scope", "bool",
       hint="Excluded from analysis. Findings against it are suppressed, "
            "not deleted, so the decision stays visible."),
    _a("out_of_scope_reason", "Reason for out of scope", "text",
       hint="Required when out of scope, so the next reviewer knows why."),
]

ATTRIBUTES: Dict[str, List[Dict[str, Any]]] = {
    "process": [
        _a("code_type", "Code type", "enum",
           ["managed", "unmanaged", "interpreted"],
           hint="Unmanaged code carries memory-safety threats managed code does not."),
        _a("running_as", "Running as", "enum",
           ["least_privilege", "standard_user", "service_account",
            "administrator", "root"],
           rule="TF-DSN-002"),
        _a("isolation_level", "Isolation level", "enum",
           ["none", "appcontainer", "container", "sandbox", "vm"]),
        _a("accepts_input_from", "Accepts input from", "enum",
           ["local_only", "internal_services", "authenticated_users", "any_remote"],
           rule="TF-DSN-001"),
        _a("implements_authn", "Implements authentication", "bool",
           rule="TF-DSN-008"),
        _a("implements_authz", "Implements authorisation", "bool"),
        _a("sanitizes_input", "Sanitises input", "bool", rule="TF-DSN-001"),
        _a("sanitizes_output", "Sanitises output", "bool"),
        _a("logs_security_events", "Logs security events", "bool",
           rule="TF-DSN-010",
           hint="Without this, an action cannot be attributed afterwards."),
        _a("handles_secrets", "Handles secrets", "bool"),
    ],
    "data_store": [
        _a("store_type", "Store type", "enum",
           ["sql", "nosql", "cache", "blob", "file", "queue", "other"]),
        _a("stores_credentials", "Stores credentials", "bool", rule="TF-DSN-003"),
        _a("stores_log_data", "Stores log data", "bool"),
        _a("encrypted", "Encrypted at rest", "bool", rule="TF-DSN-003"),
        _a("signed", "Integrity protected", "bool"),
        _a("write_access", "Writable by the application", "bool"),
        _a("backup", "Backed up", "bool", rule="TF-DSN-009"),
        _a("shared", "Shared with other systems", "bool", rule="TF-DSN-012"),
        _a("removable_storage", "On removable storage", "bool"),
    ],
    "external_entity": [
        _a("entity_type", "Kind", "enum", ["human", "service", "device", "unknown"]),
        _a("authenticates_itself", "Authenticates itself", "bool",
           rule="TF-DSN-007"),
        _a("controlled_by_us", "Under our control", "bool",
           hint="If not, neither its patching nor its logging is yours."),
    ],
    "data_flow": [
        _a("physical_network", "Physical network", "enum",
           ["loopback", "wire", "wifi", "vpn", "cellular", "internet"]),
        _a("source_authenticated", "Source authenticated", "bool"),
        _a("destination_authenticated", "Destination authenticated", "bool"),
        _a("provides_confidentiality", "Provides confidentiality", "bool"),
        _a("provides_integrity", "Provides integrity", "bool", rule="TF-DSN-011"),
        _a("contains_cookies", "Carries cookies or session tokens", "bool",
           rule="TF-DSN-006"),
        _a("forgery_protection", "Forgery protection", "enum",
           ["none", "csrf_token", "samesite", "double_submit", "not_applicable"],
           rule="TF-DSN-006"),
        _a("payload_format", "Payload format", "enum",
           ["json", "xml", "soap", "form", "binary", "other"]),
        _a("rate_limited", "Rate limited", "bool"),
    ],
}


def schema_for(element: str) -> List[Dict[str, Any]]:
    """Attributes that apply to an element, universal ones last."""
    return list(ATTRIBUTES.get(element, [])) + list(UNIVERSAL)


def catalog() -> Dict[str, Any]:
    """Everything the page needs, in one payload."""
    return {"components": COMPONENTS, "categories": CATEGORIES,
            "icons": ICONS, "attributes": ATTRIBUTES, "universal": UNIVERSAL}


def coerce(element: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """Validate attributes coming from the page or an overlay.

    Unknown keys are dropped rather than trusted: they would otherwise become
    `attr.*` facts that no rule reads and no reviewer can interpret. Enum values
    outside the declared set are dropped for the same reason. Booleans stay
    three-state -- `None` means unanswered, which is not the same as `False`.
    """
    known = {a["key"]: a for a in schema_for(element)}
    out: Dict[str, Any] = {}
    for key, value in (raw or {}).items():
        spec = known.get(str(key))
        if spec is None or value is None:
            continue
        if spec["kind"] == "bool":
            if isinstance(value, bool):
                out[key] = value
            elif str(value).lower() in ("true", "yes", "1"):
                out[key] = True
            elif str(value).lower() in ("false", "no", "0"):
                out[key] = False
        elif spec["kind"] == "enum":
            if str(value) in spec["values"]:
                out[key] = str(value)
        else:
            text = str(value).strip()
            if text:
                out[key] = text[:500]
    return out


def unanswered(element: str, attrs: Dict[str, Any]) -> List[str]:
    """Which rule-bearing questions nobody has answered for this element."""
    return [a["key"] for a in schema_for(element)
            if a.get("rule") and attrs.get(a["key"]) is None]


# ---------------------------------------------------------------------------
# Threat-model documentation.
#
# The parts of a threat model that are prose rather than diagram: who owns it,
# what was assumed, what was asked. TMT carries the same fields in
# MetaInformation, so these round-trip through .tm7 rather than living only
# here.
#
# Security questions are the part people skip. They are kept as an explicit
# question/answer list because "we considered authentication" is not a finding
# and should not pretend to be one -- but an unanswered question is a real gap,
# and a reviewer six months later needs to see which questions were asked.
# ---------------------------------------------------------------------------

DOC_FIELDS: List[Dict[str, Any]] = [
    _a("title", "Title", "text", hint="What this model covers."),
    _a("owner", "Owner", "text", hint="Who is accountable for the decisions in it."),
    _a("reviewer", "Reviewer", "text", hint="Who checked it."),
    _a("stakeholders", "Stakeholders", "textarea",
       hint="Teams affected by these decisions, one per line."),
    _a("scope", "In scope", "textarea", hint="What this model covers."),
    _a("out_of_scope", "Out of scope", "textarea",
       hint="What it deliberately does not, and why."),
    _a("assumptions", "Assumptions", "textarea",
       hint="One per line. An assumption nobody wrote down is a finding waiting "
            "to happen."),
    _a("dependencies", "External dependencies", "textarea",
       hint="Systems you rely on but do not control."),
    _a("data_classification", "Data classification", "text",
       hint="The most sensitive class of data in scope."),
    _a("compliance", "Compliance drivers", "text",
       hint="GDPR, PCI-DSS, HIPAA, SOC 2 …"),
]

# Asked in every review worth the name. Each maps to the STRIDE letter it
# addresses, so an unanswered question can be reported against the right
# category rather than as undifferentiated debt.
SECURITY_QUESTIONS: List[Dict[str, str]] = [
    {"id": "authn", "stride": "S",
     "q": "How does every entity prove who it is?"},
    {"id": "authz", "stride": "E",
     "q": "How is authorisation decided, and where is it enforced?"},
    {"id": "secrets", "stride": "I",
     "q": "Where do secrets live, who can read them, and how are they rotated?"},
    {"id": "transit", "stride": "T",
     "q": "Which flows cross a trust boundary, and what protects them?"},
    {"id": "rest", "stride": "I",
     "q": "What is encrypted at rest, and who holds the keys?"},
    {"id": "input", "stride": "T",
     "q": "Where does untrusted input enter, and what validates it?"},
    {"id": "audit", "stride": "R",
     "q": "What is logged, where does it go, and can it be tampered with?"},
    {"id": "availability", "stride": "D",
     "q": "What happens when the busiest dependency is unavailable?"},
    {"id": "keys", "stride": "S",
     "q": "How are certificates and keys issued, renewed and revoked?"},
    {"id": "thirdparty", "stride": "I",
     "q": "What do third parties receive, and what have they agreed to?"},
    {"id": "recovery", "stride": "D",
     "q": "How is the system restored, and when was that last rehearsed?"},
    {"id": "incident", "stride": "R",
     "q": "How would a compromise be detected, and by whom?"},
]


def doc_defaults() -> Dict[str, Any]:
    return {"fields": {}, "answers": {}}
