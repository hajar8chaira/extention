"""Addon mitmproxy de Security Center.

mitmdump charge ce fichier avec `-s`. Pour chaque échange HTTP complet, il
compose la même charge utile que le connecteur Burp et la dépose sur le backend
local de Security Center. Il n'y a donc qu'un seul modèle d'investigation HTTP :
une capture de proxy managé et une capture Burp se rangent, se dédoublonnent et
se rejouent exactement pareil.

Configuration par variables d'environnement, jamais par argument de ligne de
commande — un jeton passé en argument serait lisible dans la liste des processus
de la machine :

    SECURITY_CENTER_INGEST_URL   adresse complète de la route d'ingestion
    SECURITY_CENTER_API_KEY      clé du backend local, si elle est configurée
    SECURITY_CENTER_MAX_BODY     taille maximale d'un corps conservé, en octets
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

from mitmproxy import ctx, http

# Les mêmes en-têtes que `SENSITIVE_HEADERS` dans src/http-scenarios.js. Leur
# valeur ne quitte jamais le processus : elle est remplacée ici, avant tout
# envoi, donc rien de sensible n'atteint le stockage, l'interface ou un journal.
SENSITIVE_HEADERS = frozenset(
    {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
)

DEFAULT_MAX_BODY = 64 * 1024
INGEST_TIMEOUT_SECONDS = 5


def _report(marker: str, detail: str) -> None:
    """Signale un fait que Security Center doit voir, quoi qu'il arrive.

    mitmdump tourne avec `-q` : le journal de mitmproxy est volontairement muet,
    sinon chaque échange s'imprimerait en clair. `ctx.log` y disparaissait donc,
    et avec lui la seule trace qu'un échange capturé n'avait jamais atteint
    Security Center. La sortie d'erreur, elle, n'est pas concernée par `-q` :
    c'est par là que l'extension apprend la perte, et l'affiche sur la carte.
    """
    sys.stderr.write(f"[security-center][{marker}] {detail}\n")
    sys.stderr.flush()


def _limit() -> int:
    try:
        value = int(os.environ.get("SECURITY_CENTER_MAX_BODY", DEFAULT_MAX_BODY))
    except ValueError:
        return DEFAULT_MAX_BODY
    return max(0, min(value, 256 * 1024))


def _headers(fields) -> tuple[dict, list]:
    """En-têtes normalisés en minuscules, valeurs sensibles remplacées."""
    headers: dict = {}
    sensitive: list = []
    for name, value in fields.items():
        lowered = str(name).lower()
        if not lowered:
            continue
        if lowered in SENSITIVE_HEADERS:
            headers[lowered] = "[REDACTED]"
            if lowered not in sensitive:
                sensitive.append(lowered)
        else:
            headers[lowered] = str(value)
    return headers, sensitive


def _body(message, limit: int) -> str:
    """Corps décodé et tronqué. Un binaire illisible ne bloque jamais l'envoi."""
    if limit <= 0:
        return ""
    try:
        text = message.get_text(strict=False)
    except Exception:  # noqa: BLE001 - un corps illisible n'est pas une erreur d'addon
        return ""
    if not text:
        return ""
    if len(text) > limit:
        return text[:limit] + "\n[TRUNCATED]"
    return text


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _scenario(flow: http.HTTPFlow) -> dict:
    limit = _limit()
    request_headers, request_sensitive = _headers(flow.request.headers)
    response_headers, response_sensitive = _headers(flow.response.headers)
    response_body = _body(flow.response, limit)

    # Le temps d'aller-retour est calculé à partir des horodatages de mitmproxy,
    # et seulement lorsque les deux existent : une durée inventée serait pire
    # qu'une durée absente.
    duration_ms = None
    started = getattr(flow.request, "timestamp_start", None)
    ended = getattr(flow.response, "timestamp_end", None)
    if started and ended and ended >= started:
        duration_ms = int((ended - started) * 1000)

    return {
        "name": f"{flow.request.method} {flow.request.path or '/'}",
        "source": "mitmproxy",
        "timestamp": _iso(started),
        "request": {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": request_headers,
            "body": _body(flow.request, limit),
            "sensitive_headers": request_sensitive,
        },
        "response": {
            "statusCode": flow.response.status_code,
            "headers": response_headers,
            "body": response_body,
            "bodySha256": _sha256(response_body),
            "sensitive_headers": response_sensitive,
        },
        "capture": {
            "flow_id": flow.id,
            "scheme": flow.request.scheme,
            "host": flow.request.pretty_host,
            "port": flow.request.port,
            "duration_ms": duration_ms,
            "request_size": len(flow.request.raw_content or b""),
            "response_size": len(flow.response.raw_content or b""),
            "content_type": response_headers.get("content-type", ""),
        },
    }


def _iso(timestamp) -> str:
    if not timestamp:
        return ""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


class SecurityCenterAddon:
    def __init__(self) -> None:
        self.url = os.environ.get("SECURITY_CENTER_INGEST_URL", "")
        self.api_key = os.environ.get("SECURITY_CENTER_API_KEY", "")
        self.sent = 0
        self.failed = 0

    def running(self) -> None:
        if self.url:
            ctx.log.info(f"[security-center] ingestion vers {self.url}")
        else:
            _report(
                "ingest-error",
                "SECURITY_CENTER_INGEST_URL absente : les échanges sont capturés "
                "mais ne sont envoyés nulle part.",
            )

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.url or flow.response is None:
            return
        payload = json.dumps(_scenario(flow)).encode("utf-8")
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["x-security-center-key"] = self.api_key
        request = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=INGEST_TIMEOUT_SECONDS):
                self.sent += 1
        except urllib.error.HTTPError as error:
            self.failed += 1
            # Le corps de la réponse d'erreur peut citer la requête refusée :
            # seul le code est journalisé. Le marqueur `ingest-error` est lu par
            # l'extension, qui en fait un état visible sur la carte — un échange
            # perdu ne doit pas exister seulement dans ce journal.
            _report("ingest-error", f"HTTP {error.code}")
        except Exception as error:  # noqa: BLE001 - le proxy ne doit jamais tomber pour ça
            self.failed += 1
            _report("ingest-error", type(error).__name__)

    def done(self) -> None:
        ctx.log.info(f"[security-center] {self.sent} échange(s) envoyé(s), {self.failed} échec(s)")


addons = [SecurityCenterAddon()]
