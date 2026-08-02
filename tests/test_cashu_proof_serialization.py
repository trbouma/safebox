import inspect
import unittest

from safebox.acorn import Acorn
from safebox.models import Proof


class CashuProofSerializationTests(unittest.TestCase):
    def test_empty_witness_is_omitted_from_mint_payload(self):
        proof = Proof(
            id="00abc",
            amount=1,
            secret="test-secret",
            C="02abc",
            Y="03abc",
        )

        self.assertEqual(
            proof.to_dict(),
            {
                "id": "00abc",
                "amount": 1,
                "secret": "test-secret",
                "C": "02abc",
            },
        )

    def test_ecash_issuance_swap_uses_minimal_proof_serialization(self):
        source = inspect.getsource(Acorn.swap_for_payment_multi)

        self.assertIn("proofs_to_send.append(each.to_dict())", source)
        self.assertNotIn("proofs_to_send.append(each.model_dump())", source)


if __name__ == "__main__":
    unittest.main()
