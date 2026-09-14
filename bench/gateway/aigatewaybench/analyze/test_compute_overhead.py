"""Unit test for compute_overhead.py (PLT-23 §1: "computed by a small python
script with a unit test"). Run with:

    python3 -m unittest bench/gateway/aigatewaybench/analyze/test_compute_overhead.py

or, from this directory:

    python3 -m unittest test_compute_overhead
"""

from __future__ import annotations

import unittest

from compute_overhead import compute_overhead


class ComputeOverheadTests(unittest.TestCase):
    def test_subtracts_direct_baseline_per_percentile(self) -> None:
        rows = [
            {
                "gateway": "direct",
                "status": "ok",
                "p50_ms": "1.000",
                "p95_ms": "2.000",
                "p99_ms": "3.000",
            },
            {
                "gateway": "tracelane",
                "status": "ok",
                "p50_ms": "1.500",
                "p95_ms": "2.700",
                "p99_ms": "4.100",
            },
        ]
        [result] = compute_overhead(rows)
        self.assertEqual(result["overhead_p50_ms"], 0.5)
        self.assertEqual(result["overhead_p95_ms"], 0.7)
        self.assertEqual(result["overhead_p99_ms"], 1.1)

    def test_missing_direct_baseline_raises(self) -> None:
        rows = [
            {
                "gateway": "tracelane",
                "status": "ok",
                "p50_ms": "1",
                "p95_ms": "2",
                "p99_ms": "3",
            }
        ]
        with self.assertRaises(ValueError):
            compute_overhead(rows)

    def test_cannot_determine_row_passes_through_with_no_fabricated_number(
        self,
    ) -> None:
        rows = [
            {
                "gateway": "direct",
                "status": "ok",
                "p50_ms": "1.0",
                "p95_ms": "2.0",
                "p99_ms": "3.0",
            },
            {
                "gateway": "litellm-rust",
                "status": "CANNOT DETERMINE — no public build",
                "p50_ms": "",
                "p95_ms": "",
                "p99_ms": "",
            },
        ]
        [result] = compute_overhead(rows)
        self.assertIsNone(result["overhead_p50_ms"])
        self.assertIsNone(result["overhead_p95_ms"])
        self.assertIsNone(result["overhead_p99_ms"])

    def test_missing_percentile_on_an_ok_row_raises_rather_than_fabricating_zero(
        self,
    ) -> None:
        rows = [
            {
                "gateway": "direct",
                "status": "ok",
                "p50_ms": "1.0",
                "p95_ms": "2.0",
                "p99_ms": "3.0",
            },
            {
                "gateway": "portkey",
                "status": "ok",
                "p50_ms": "",
                "p95_ms": "2.0",
                "p99_ms": "3.0",
            },
        ]
        with self.assertRaises(ValueError):
            compute_overhead(rows)


if __name__ == "__main__":
    unittest.main()
