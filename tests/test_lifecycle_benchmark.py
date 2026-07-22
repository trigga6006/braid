from __future__ import annotations

import unittest

from benchmarks.lifecycle_benchmark import run


class LifecycleBenchmarkTests(unittest.TestCase):
    def test_small_complete_lifecycle_benchmark_is_executable(self) -> None:
        report = run((3,), 1)
        result = report["results"]["3"]
        self.assertGreater(result["median_elapsed_ms"], 0)
        self.assertGreater(result["max_peak_python_bytes"], 0)
        self.assertGreater(result["median_bundle_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
