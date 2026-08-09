import unittest
from unittest.mock import patch

from app.nwc import _serialize_nwc_payment_preimage
from safebox.acorn import normalize_payment_preimage, recover_melt_payment_preimage


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class FakeAsyncClient:
    responses = []
    requested_urls = []

    def __init__(self, *args, **kwargs):
        self._responses = iter(self.responses)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def get(self, url):
        self.requested_urls.append(url)
        return FakeResponse(next(self._responses))


class PaymentPreimageTests(unittest.IsolatedAsyncioTestCase):
    def test_normalization_rejects_null_like_values(self):
        self.assertIsNone(normalize_payment_preimage(None))
        self.assertIsNone(normalize_payment_preimage(" null "))
        self.assertEqual(normalize_payment_preimage(" abcd "), "abcd")

    def test_nwc_success_preimage_is_always_a_string(self):
        self.assertEqual(_serialize_nwc_payment_preimage(None), "")
        self.assertEqual(_serialize_nwc_payment_preimage("abcd"), "abcd")

    async def test_missing_preimage_is_recovered_from_final_quote(self):
        FakeAsyncClient.responses = [
            {"state": "PAID", "payment_preimage": None},
            {"state": "PAID", "payment_preimage": "feedface"},
        ]
        FakeAsyncClient.requested_urls = []

        with (
            patch("safebox.acorn.httpx.AsyncClient", FakeAsyncClient),
            patch("safebox.acorn.asyncio.sleep", return_value=None),
        ):
            preimage = await recover_melt_payment_preimage(
                "https://mint.example/",
                "quote-1",
            )

        self.assertEqual(preimage, "feedface")
        self.assertEqual(
            FakeAsyncClient.requested_urls,
            [
                "https://mint.example/v1/melt/quote/bolt11/quote-1",
                "https://mint.example/v1/melt/quote/bolt11/quote-1",
            ],
        )


if __name__ == "__main__":
    unittest.main()
