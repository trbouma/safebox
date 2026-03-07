import logging
import base64
from html import escape
from typing import Any
from urllib.parse import quote, unquote, urlparse, urlencode, parse_qsl, urlunparse

import bolt11
import cbor2
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.branding import build_templates

from app.config import Settings
from app.utils import check_ln_address, decode_lnurl, parse_nauth

settings = Settings()
logger = logging.getLogger(__name__)


templates = build_templates()

router = APIRouter()


@router.get("/scan", tags=["scanner"], response_class=HTMLResponse)
async def get_scanner(  request: Request, 
                        qr_code: str = "none", 
                        wallet_name: str = None,
                        referer: str = None):
    """return user information"""
    
    # referer = urllib.parse.urlparse(request.headers.get("referer")).path

    

    
    return templates.TemplateResponse("acquirescan.html", 
                                      {"request": request,
                                       "referer": referer,
                                       "wallet_name": wallet_name
                                      
                                       
                                       
                                       } )
   
@router.api_route("/scanresult", tags=["acquire"], methods=["GET", "POST"],response_class=HTMLResponse)
async def get_scan_result(  request: Request, 
                            qr_code: str = "none",
                            referer:str = "none"):
    """return wallet mode information"""

    if request.method == "POST":
        data = {}
        try:
            data = await request.json()
        except Exception:
            try:
                form_data = await request.form()
                data = dict(form_data)
            except Exception:
                data = {}
        qr_code = data.get("data", None)
        referer = data.get("referer", referer)
    referer = (referer or "none").strip()
    qr_code = _normalize_scan_payload(qr_code)
    if not qr_code:
        return RedirectResponse("/safebox/access")

    logger.debug("scan payload normalized: %s", qr_code)

    if check_ln_address(qr_code):
        action_data, amount, currency = _extract_ln_address_fields(unquote(qr_code))
        return _redirect_access(
            lnaddress=action_data,
            amount=amount,
            currency=currency,
        )

    if qr_code[:5].lower() == "lnurl":
        try:
            decoded_url = decode_lnurl(qr_code)
            logger.debug("decoded lnurl: %s", decoded_url)
            if "lnurlp" in decoded_url:
                ln_parts = urlparse(decoded_url)
                derived_address = f"{ln_parts.path.split('/')[-1]}@{ln_parts.netloc}"
                action_data, amount, currency = _extract_ln_address_fields(derived_address)
                return _redirect_access(
                    lnaddress=action_data,
                    amount=amount,
                    currency=currency,
                )
        except Exception:
            logger.exception("Failed to decode LNURL in scanresult")
        return RedirectResponse("/safebox/access")

    if qr_code[:4].lower() == "lnbc":
        action_amount = 0
        action_comment = ""
        try:
            decoded_invoice = bolt11.decode(qr_code)
            if decoded_invoice.amount_msat:
                action_amount = decoded_invoice.amount_msat // 1000
            action_comment = decoded_invoice.description or ""
        except Exception:
            logger.exception("Failed to decode lightning invoice in scanresult")
        return _redirect_access(
            invoice=qr_code,
            invoice_amount=action_amount,
            invoice_comment=action_comment,
        )

    if qr_code[:6] == "cashuA":
        return _redirect_access(ecash=qr_code)

    if qr_code[:5].lower() == "creqa":
        parsed_creq = _parse_creq_payment_request(qr_code)
        if not parsed_creq:
            logger.warning("Invalid NUT-18 payment request scanned")
            return _redirect_access(
                action_comment="Invalid Cashu payment request.",
            )
        return _redirect_access(
            action_mode="creq",
            action_data=qr_code,
            action_amount=parsed_creq.get("a"),
            action_comment=parsed_creq.get("d", "Cashu payment request scanned."),
            currency=parsed_creq.get("u", "SAT").upper(),
        )

    if qr_code[:8].lower() == "nprofile":
        return _redirect_access(nprofile=qr_code)

    if qr_code[:5].lower() == "nauth":
        try:
            parsed_nauth = parse_nauth(qr_code)
        except Exception:
            logger.warning("Invalid nauth payload scanned: %s", qr_code)
            return _redirect_access(action_comment="Invalid or unsupported authentication QR.")
        logger.debug("scanner parsed nauth: %s", parsed_nauth)

        scope = parsed_nauth.get("values", {}).get("scope", "")
        if scope.startswith("offer_request"):
            return _redirect_offer_request_scan(qr_code, referer)
        if scope.startswith("present_request"):
            return _redirect_present_request_scan(qr_code)
        if "prover" in scope:
            return RedirectResponse(f"/credentials/presentationrequest?nauth={quote(qr_code)}")
        if "vcred" in scope:
            return RedirectResponse(f"/credentials/present?nauth={quote(qr_code)}")
        if "offer" in scope:
            # Use POST handoff to avoid URL/query loss on some mobile scanners.
            return _post_accept_scan({"nauth": qr_code})
        if "verifier" in scope:
            return _post_present_scan({"nauth": qr_code})
        if "vissue" in scope:
            return RedirectResponse(f"/credentials/offer?nauth={quote(qr_code)}")

        if referer == "health-data":
            return RedirectResponse(f"/safebox/health?nauth={quote(qr_code)}")
        if referer == "my-credentials":
            return RedirectResponse(f"/credentials/present?nauth={quote(qr_code)}")
        if referer == "credential-offer":
            return RedirectResponse(f"/credentials/offer?nauth={quote(qr_code)}")
        return _post_access_scan({"nauth": qr_code})

    if qr_code[:12].lower() == "nostr:nevent":
        logger.debug("unsupported nostr nevent scan: %s", qr_code)
        return RedirectResponse("/safebox/access")

    if qr_code[:5].lower() == "https":
        return RedirectResponse(qr_code)

    return RedirectResponse("/safebox/access")


def _normalize_scan_payload(raw_payload: str | None) -> str:
    if not raw_payload:
        return ""
    payload = raw_payload.strip()
    payload = payload.replace("lightning:", "").replace("bitcoin:", "").replace("LIGHTNING:", "")
    payload = payload.replace("https://wallet.cashu.me/?token=", "")
    payload = payload.replace(" ", "+")
    return payload


def _extract_ln_address_fields(address: str) -> tuple[str, float, str | None]:
    amount = 0.0
    currency = None
    address_parts = address.split("@")
    if len(address_parts) != 2:
        return address, amount, currency

    local_part = address_parts[0].split("__")
    name = local_part[0]
    if len(local_part) >= 2:
        try:
            amount = float(local_part[1])
        except (TypeError, ValueError):
            amount = 0.0
    if len(local_part) >= 3:
        currency = local_part[2]
    normalized_address = f"{name}@{address_parts[1]}"
    return normalized_address, amount, currency


def _parse_creq_payment_request(qr_code: str) -> dict[str, Any] | None:
    payload = qr_code[5:]
    if not payload:
        return None

    parsed_obj = _decode_cbor_b64(payload)
    if not isinstance(parsed_obj, dict):
        return None

    amount = parsed_obj.get("a")
    unit = parsed_obj.get("u")
    if amount is not None:
        if not isinstance(amount, int) or amount < 0:
            return None
        if not isinstance(unit, str) or not unit.strip():
            return None
    if unit is not None and not isinstance(unit, str):
        return None

    description = parsed_obj.get("d")
    if description is not None and not isinstance(description, str):
        return None

    return parsed_obj


def _decode_cbor_b64(encoded: str) -> dict[str, Any] | None:
    # Accept urlsafe base64 (spec) and plain base64 (legacy local generators).
    padded = _add_b64_padding(encoded.strip())
    decoders = (
        base64.urlsafe_b64decode,
        base64.b64decode,
    )
    for decode_func in decoders:
        try:
            raw = decode_func(padded.encode("utf-8"))
            payload = cbor2.loads(raw)
            if isinstance(payload, dict):
                return payload
        except Exception:
            continue
    return None


def _add_b64_padding(value: str) -> str:
    pad_len = (-len(value)) % 4
    if pad_len == 0:
        return value
    return f"{value}{'=' * pad_len}"


def _redirect_access(**params: object) -> RedirectResponse:
    clean_params = {key: value for key, value in params.items() if value is not None}
    if not clean_params:
        return RedirectResponse("/safebox/access")
    return RedirectResponse(f"/safebox/access?{urlencode(clean_params)}")


def _redirect_offer_request_scan(nauth: str, referer: str | None) -> HTMLResponse | RedirectResponse:
    offer_kind = None
    # Recipient-initiated offer scans should default to immediate transmit.
    recipient_mode = "auto_send"
    try:
        parsed = parse_nauth(nauth)
        scope = (parsed.get("values", {}).get("scope") or "").strip()
        # Extended receive-offer scope format:
        #   offer_request:<grant_kind>:<offer_kind>
        # Fall back gracefully if format is absent or malformed.
        if scope.startswith("offer_request:"):
            parts = scope.split(":", 3)
            if len(parts) >= 3 and parts[2].isdigit():
                offer_kind = int(parts[2])
    except Exception:
        offer_kind = None

    if referer:
        parsed_ref = urlparse(referer)
        # Critical: offer_request handshake is initiated in /records/offerlist.
        # /records/displayoffer renders a specific offer, but does not emit the
        # recipient-auth response needed by /records/ws/request stage-1.
        # Therefore always normalize offer_request scans to /records/offerlist.
        if parsed_ref.path in {"/records/offerlist", "/records/displayoffer"}:
            query_params = dict(parse_qsl(parsed_ref.query, keep_blank_values=True))
            query_params["nauth"] = nauth
            query_params["recipient_initiated"] = "1"
            # For offer_request scans, always force auto-send. Keeping a stale
            # referer-provided "review" mode causes a dead-end because the
            # manual send button is intentionally hidden in this flow.
            query_params["recipient_mode"] = recipient_mode
            if offer_kind is not None:
                query_params["kind"] = str(offer_kind)
            # Scanner-only POST handoff keeps nauth and flow params out of URL.
            return _post_offerlist_scan(query_params)

    if offer_kind is not None:
        return _post_offerlist_scan(
            {
                "nauth": nauth,
                "kind": str(offer_kind),
                "recipient_initiated": "1",
                "recipient_mode": recipient_mode,
            }
        )
    return _post_offerlist_scan(
        {
            "nauth": nauth,
            "recipient_initiated": "1",
            "recipient_mode": recipient_mode,
        }
    )


def _post_offerlist_scan(fields: dict[str, str]) -> HTMLResponse:
    return _post_form_scan(
        "/records/offerlist-scan",
        fields,
        form_id="scanOfferPost",
        message="Connecting offer channel...",
    )


def _post_accept_scan(fields: dict[str, str]) -> HTMLResponse:
    return _post_form_scan(
        "/records/accept",
        fields,
        form_id="scanAcceptPost",
        message="Connecting receive channel...",
    )


def _post_present_scan(fields: dict[str, str]) -> HTMLResponse:
    return _post_form_scan("/records/present", fields, message="Connecting presenter...")


def _post_access_scan(fields: dict[str, str]) -> HTMLResponse:
    return _post_form_scan("/safebox/access", fields, message="Connecting Safebox...")


def _post_form_scan(
    action: str,
    fields: dict[str, str],
    form_id: str = "scanPostForm",
    message: str = "Connecting...",
) -> HTMLResponse:
    inputs = []
    for key, value in fields.items():
        if value is None:
            continue
        inputs.append(
            f'<input type="hidden" name="{escape(str(key), quote=True)}" value="{escape(str(value), quote=True)}" />'
        )
    html = f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Safebox Redirect</title>
    <style>
      :root {{
        --sb-navy: #000060;
        --sb-light: #f6f6f6;
        --sb-blue-1: #5267ec;
      }}
      html, body {{
        margin: 0;
        height: 100%;
        background: radial-gradient(circle at 20% 20%, rgba(82, 103, 236, 0.25), rgba(0, 0, 96, 0.95));
        color: var(--sb-light);
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Helvetica, Arial, sans-serif;
      }}
      .wrap {{
        min-height: 100%;
        display: grid;
        place-items: center;
        padding: 24px;
        box-sizing: border-box;
      }}
      .card {{
        width: min(360px, 84vw);
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 16px;
        background: rgba(8, 13, 38, 0.75);
        backdrop-filter: blur(4px);
        box-shadow: 0 18px 34px rgba(0, 0, 0, 0.35);
        padding: 16px 14px;
        text-align: center;
      }}
      .brand {{
        font-weight: 700;
        letter-spacing: 0.03em;
        margin-bottom: 8px;
      }}
      .msg {{
        margin: 0;
        opacity: 0.94;
        font-size: 0.95rem;
      }}
      .spinner {{
        width: 34px;
        height: 34px;
        margin: 14px auto 4px;
        border-radius: 50%;
        border: 3px solid rgba(255, 255, 255, 0.25);
        border-top-color: var(--sb-blue-1);
        animation: spin 0.8s linear infinite;
      }}
      @keyframes spin {{
        to {{ transform: rotate(360deg); }}
      }}
      @media (max-width: 520px) {{
        .wrap {{ padding: 14px; }}
        .card {{
          width: min(320px, 80vw);
          border-radius: 14px;
          padding: 14px 12px;
        }}
        .brand {{ font-size: 0.95rem; margin-bottom: 6px; }}
        .msg {{ font-size: 0.9rem; }}
        .spinner {{ width: 30px; height: 30px; margin-top: 12px; }}
      }}
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        <div class="brand">SAFEBOX</div>
        <p class="msg">{escape(message)}</p>
        <div class="spinner" aria-hidden="true"></div>
      </div>
    </div>
    <form id="{escape(form_id, quote=True)}" method="post" action="{escape(action, quote=True)}">
      {''.join(inputs)}
    </form>
    <script>document.getElementById('{escape(form_id, quote=True)}').submit();</script>
  </body>
</html>
"""
    return HTMLResponse(content=html)


def _redirect_present_request_scan(nauth: str) -> RedirectResponse:
    grant_kind = None
    target = None
    try:
        parsed = parse_nauth(nauth)
        scope = (parsed.get("values", {}).get("scope") or "").strip()
        # Format:
        #   present_request:<grant_kind>[:target=<npub:label>]
        if scope.startswith("present_request:"):
            parts = scope.split(":", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                grant_kind = int(parts[1])
            if len(parts) >= 3:
                suffix = (parts[2] or "").strip()
                if suffix.startswith("target="):
                    target_candidate = suffix[len("target="):].strip()
                    if target_candidate:
                        target = target_candidate
    except Exception:
        grant_kind = None
        target = None

    target_qs = f"&target={quote(target)}" if target else ""
    if grant_kind is not None:
        return RedirectResponse(
            f"/records/request?grant_kind={grant_kind}&mode=request&presenter_nauth={quote(nauth)}{target_qs}"
        )
    return RedirectResponse(f"/records/request?mode=request&presenter_nauth={quote(nauth)}{target_qs}")
    
      
