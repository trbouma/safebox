import json
from typing import Any, Optional

from monstr.encrypt import Keys
from monstr.event.event import Event

from app.config import Settings
from app.utils import get_label_by_id, get_tag_value
from safebox.acorn import Acorn
from safebox.func_utils import get_attestation, get_profile_for_pub_hex


settings = Settings()


def parse_event_payload(payload) -> Optional[Event]:
    candidate = None
    if isinstance(payload, dict):
        candidate = json.dumps(payload)
    elif isinstance(payload, str):
        stripped = payload.strip()
        if not stripped.startswith("{"):
            return None
        candidate = payload
    else:
        return None

    try:
        event_to_validate: Event = Event().load(candidate)
    except Exception:
        return None

    if (
        event_to_validate.kind is None
        or event_to_validate.pub_key is None
        or event_to_validate.sig is None
    ):
        return None
    return event_to_validate


async def resolve_record_verification_facts(
    event_to_validate: Event,
    acorn_obj: Acorn,
    presenter: str | None = None,
    include_trust_details: bool = False,
    trust_context: dict[str, Any] | None = None,
) -> dict:
    print(f"event to validate tags: {event_to_validate.tags}")
    tag_owner = get_tag_value(event_to_validate.tags, "safebox_owner")
    tag_issuer = get_tag_value(event_to_validate.tags, "safebox_issuer")
    tag_holder = get_tag_value(event_to_validate.tags, "safebox_holder")
    type_name = get_label_by_id(settings.GRANT_KINDS, event_to_validate.kind)
    owner_pub_hex = None
    owner_npub = None
    owner_display = tag_owner

    if tag_owner:
        try:
            owner_keys = Keys(pub_k=tag_owner)
            owner_pub_hex = owner_keys.public_key_hex()
            owner_npub = owner_keys.public_key_bech32()
            owner_display = owner_npub
        except Exception:
            owner_pub_hex = None
            owner_npub = None

    profile_cache = (trust_context or {}).setdefault("profile_cache", {})
    owner_info = "No Owner Profile Found"
    picture = None
    if owner_pub_hex:
        if owner_pub_hex not in profile_cache:
            profile_cache[owner_pub_hex] = await get_profile_for_pub_hex(owner_pub_hex, settings.RELAYS)
        owner_info, picture = profile_cache[owner_pub_hex]
    print(f"safebox issuer: {owner_display} {owner_info}")
    print("let's check signature")
    print(f"event to validate: {event_to_validate.data()}")

    is_valid = "True" if event_to_validate.is_valid() else "Cannot Validate"
    content = f"{event_to_validate.content}"

    facts = {
        "tag_owner": tag_owner,
        "tag_owner_hex": owner_pub_hex,
        "tag_owner_npub": owner_npub,
        "tag_owner_display": owner_display,
        "tag_issuer": tag_issuer,
        "tag_holder": tag_holder,
        "type_name": type_name,
        "owner_info": owner_info,
        "picture": picture,
        "is_valid": is_valid,
        "content": content,
    }

    if not include_trust_details:
        return facts

    is_attested = False
    is_trusted = False
    is_presenter = False
    wot_scores = []
    attestation_cache = (trust_context or {}).setdefault("attestation_cache", {})
    wot_score_cache = (trust_context or {}).setdefault("wot_score_cache", {})
    trusted_entities = (trust_context or {}).get("trusted_entities")

    if owner_display:
        attestation_cache_key = owner_pub_hex or owner_display
        if attestation_cache_key not in attestation_cache:
            attestation_cache[attestation_cache_key] = await get_attestation(
                owner_npub=owner_npub or owner_display,
                safebox_npub=acorn_obj.pubkey_bech32,
                relays=settings.RELAYS,
            )
        is_attested = attestation_cache[attestation_cache_key]

        print(f"trusted_entities: {trusted_entities} tag owner {owner_display}")
        if trusted_entities is None:
            trusted_entities = await acorn_obj.get_trusted_entities(relays=settings.RELAYS)
            if trust_context is not None:
                trust_context["trusted_entities"] = trusted_entities
        is_trusted = bool(owner_pub_hex and owner_pub_hex in trusted_entities)

        print(f"is attested: {is_attested}")
        wot_cache_key = owner_pub_hex or owner_display
        if wot_cache_key not in wot_score_cache:
            wot_score_cache[wot_cache_key] = await acorn_obj.get_wot_scores(
                pub_key_to_score=owner_pub_hex or owner_display,
                relays=settings.WOT_RELAYS,
            )
        wot_scores = wot_score_cache[wot_cache_key]

    print(f"test for presenter: {presenter} tag holder: {tag_holder}")
    if presenter == tag_holder:
        is_presenter = True

    facts.update(
        {
            "is_attested": is_attested,
            "is_trusted": is_trusted,
            "is_presenter": is_presenter,
            "wot_scores": wot_scores,
        }
    )
    return facts


async def build_record_trust_context(
    acorn_obj: Acorn,
    include_trusted_entities: bool = False,
) -> dict[str, Any]:
    trust_context: dict[str, Any] = {
        "profile_cache": {},
        "attestation_cache": {},
        "wot_score_cache": {},
        "trusted_entities": None,
    }

    if include_trusted_entities:
        trust_context["trusted_entities"] = await acorn_obj.get_trusted_entities(relays=settings.RELAYS)

    return trust_context
