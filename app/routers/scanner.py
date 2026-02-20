import logging
from urllib.parse import quote, unquote, urlparse, urlencode

import bolt11
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import Settings
from app.utils import check_ln_address, decode_lnurl, parse_nauth

settings = Settings()
logger = logging.getLogger(__name__)


templates = Jinja2Templates(directory="app/templates")

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
        data = await request.json()
        qr_code = data.get("data", None)
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

    if qr_code[:8].lower() == "nprofile":
        return _redirect_access(nprofile=qr_code)

    if qr_code[:5].lower() == "nauth":
        parsed_nauth = parse_nauth(qr_code)
        logger.debug("scanner parsed nauth: %s", parsed_nauth)

        scope = parsed_nauth.get("values", {}).get("scope", "")
        if "prover" in scope:
            return RedirectResponse(f"/credentials/presentationrequest?nauth={quote(qr_code)}")
        if "vcred" in scope:
            return RedirectResponse(f"/credentials/present?nauth={quote(qr_code)}")
        if "offer" in scope:
            return RedirectResponse(f"/records/accept?nauth={quote(qr_code)}")
        if "verifier" in scope:
            return RedirectResponse(f"/records/present?nauth={quote(qr_code)}")
        if "vissue" in scope:
            return RedirectResponse(f"/credentials/offer?nauth={quote(qr_code)}")

        if referer == "health-data":
            return RedirectResponse(f"/safebox/health?nauth={quote(qr_code)}")
        if referer == "my-credentials":
            return RedirectResponse(f"/credentials/present?nauth={quote(qr_code)}")
        if referer == "credential-offer":
            return RedirectResponse(f"/credentials/offer?nauth={quote(qr_code)}")
        return RedirectResponse(f"/safebox/access?nauth={quote(qr_code)}")

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


def _redirect_access(**params: object) -> RedirectResponse:
    clean_params = {key: value for key, value in params.items() if value is not None}
    if not clean_params:
        return RedirectResponse("/safebox/access")
    return RedirectResponse(f"/safebox/access?{urlencode(clean_params)}")
    
      
