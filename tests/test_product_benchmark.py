from __future__ import annotations

import unittest

from benchmarks.product_benchmark import run


class ProductBenchmarkTests(unittest.TestCase):
    def test_real_product_pipeline_passes_hard_gates(self) -> None:
        report = run((25, 100))
        self.assertTrue(report["hard_gates_passed"], report)
        self.assertEqual(report["implementation"], "real")


if __name__ == "__main__":
    unittest.main()
