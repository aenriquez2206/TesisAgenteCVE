import unittest

from evaluate_agent import FAMILIES, build_cases, retrieval_matches, latency_summary


def inventory_for(cves):
    types = ("nvd", "capec", "cwe", "cpe", "exploit")
    return {cve: {kind: [{"id": f"{cve}:{kind}", "metadata": {"cve_id": cve,
                "content_type": kind}}] for kind in types}
            for cve in cves}


class EvaluationPlanTests(unittest.TestCase):
    def test_unknown_cve_requires_empty_evidence(self):
        case = {'expected_status': 200, 'expect_no_evidence': True}
        self.assertTrue(retrieval_matches(case, 200, []))
        self.assertFalse(retrieval_matches(case, 200, [{'cve_id': 'CVE-2024-0001', 'source': 'nvd'}]))
        self.assertFalse(retrieval_matches(case, 502, []))

    def test_latency_statistics_do_not_count_fast_errors_as_success(self):
        result = latency_summary([{'status_code': 200, 'duration_ms': 100},
                                  {'status_code': 502, 'duration_ms': 1}])
        self.assertEqual(result['errors'], 1)
        self.assertEqual(result['successful_total']['median_ms'], 100)

    def test_case_matrix_has_sixty_reproducible_cases(self):
        inventory = inventory_for([f"CVE-2024-{number:04d}" for number in range(1, 21)])
        cases = build_cases(inventory)
        self.assertEqual(len(cases), 60)
        self.assertEqual(len({case["case_id"] for case in cases}), 60)
        self.assertEqual({case["family"] for case in cases}, set(FAMILIES) | {"robustness"})
        self.assertEqual(sum(not case["supported"] for case in cases), 7)
        ambiguous = next(case for case in cases if case["query"] == "¿A cuál se refiere?")
        self.assertEqual(ambiguous["expected_status"], 422)

    def test_each_primary_family_has_four_cases(self):
        inventory = inventory_for([f"CVE-2024-{number:04d}" for number in range(1, 21)])
        families = {}
        for case in build_cases(inventory):
            families[case["family"]] = families.get(case["family"], 0) + 1
        for family in FAMILIES:
            self.assertEqual(families[family], 4)
        self.assertEqual(families["robustness"], 20)

    def test_data_families_include_a_record_absence_case(self):
        inventory = inventory_for([f"CVE-2024-{number:04d}" for number in range(1, 21)])
        inventory["CVE-2024-0020"] = {"nvd": inventory["CVE-2024-0020"]["nvd"]}
        cases = build_cases(inventory)
        for family in ("capec", "cwe", "cpe", "exploit"):
            self.assertEqual(sum(bool(case["expected_absent_source_types"])
                                 for case in cases if case["family"] == family), 1)


if __name__ == "__main__":
    unittest.main()
