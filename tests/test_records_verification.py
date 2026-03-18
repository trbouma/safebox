import unittest
from unittest.mock import AsyncMock, patch

from monstr.encrypt import Keys

from app.records_verification import (
    build_record_trust_context,
    parse_event_payload,
    resolve_record_verification_facts,
)


class FakeEvent:
    def __init__(self, owner_value: str, holder_value: str | None = None):
        self.tags = [
            ["safebox_owner", owner_value],
            ["safebox_issuer", "issuer-hex"],
            ["safebox_holder", holder_value or "presenter-npub"],
        ]
        self.kind = 37375
        self.content = "record-content"
        self.created_at = 1234567890
        self.pub_key = "f" * 64
        self.sig = "a" * 128

    def is_valid(self):
        return True

    def data(self):
        return {"kind": self.kind, "content": self.content}


class FakeAcorn:
    def __init__(self, trusted_entities=None, wot_scores=None):
        self.pubkey_bech32 = "npub1testpresenterxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        self._trusted_entities = trusted_entities or []
        self._wot_scores = wot_scores or [["score", "5"]]
        self.get_trusted_entities = AsyncMock(return_value=self._trusted_entities)
        self.get_wot_scores = AsyncMock(return_value=self._wot_scores)


class RecordsVerificationTests(unittest.IsolatedAsyncioTestCase):
    def test_parse_event_payload_rejects_plain_text(self):
        self.assertIsNone(parse_event_payload("not-json"))

    async def test_build_record_trust_context_optionally_loads_trusted_entities(self):
        acorn = FakeAcorn(trusted_entities=["abc"])

        context = await build_record_trust_context(acorn, include_trusted_entities=True)

        self.assertEqual(context["trusted_entities"], ["abc"])
        acorn.get_trusted_entities.assert_awaited_once()

    async def test_resolve_record_verification_facts_normalizes_owner_and_uses_cache(self):
        owner_keys = Keys()
        owner_hex = owner_keys.public_key_hex()
        owner_npub = owner_keys.public_key_bech32()
        event = FakeEvent(owner_value=owner_hex, holder_value="presenter-npub")
        acorn = FakeAcorn(trusted_entities=[owner_hex], wot_scores=[["reputation", "7"]])
        trust_context = await build_record_trust_context(acorn, include_trusted_entities=True)

        with (
            patch("app.records_verification.get_profile_for_pub_hex", new=AsyncMock(return_value=("Owner Name nip05", "https://example.com/pic.png"))) as profile_mock,
            patch("app.records_verification.get_attestation", new=AsyncMock(return_value=True)) as attestation_mock,
        ):
            facts_first = await resolve_record_verification_facts(
                event_to_validate=event,
                acorn_obj=acorn,
                presenter="presenter-npub",
                include_trust_details=True,
                trust_context=trust_context,
            )
            facts_second = await resolve_record_verification_facts(
                event_to_validate=event,
                acorn_obj=acorn,
                presenter="presenter-npub",
                include_trust_details=True,
                trust_context=trust_context,
            )

        self.assertEqual(facts_first["tag_owner_hex"], owner_hex)
        self.assertEqual(facts_first["tag_owner_npub"], owner_npub)
        self.assertEqual(facts_first["tag_owner_display"], owner_npub)
        self.assertTrue(facts_first["is_trusted"])
        self.assertTrue(facts_first["is_attested"])
        self.assertTrue(facts_first["is_presenter"])
        self.assertEqual(facts_first["wot_scores"], [["reputation", "7"]])
        self.assertEqual(facts_second["owner_info"], "Owner Name nip05")
        profile_mock.assert_awaited_once_with(owner_hex, unittest.mock.ANY)
        attestation_mock.assert_awaited_once()
        acorn.get_wot_scores.assert_awaited_once()
        acorn.get_trusted_entities.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
