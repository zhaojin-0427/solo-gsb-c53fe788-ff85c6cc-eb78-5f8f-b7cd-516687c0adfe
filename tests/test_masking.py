import unittest

from app.masking import apply_rules, validate_rules, RuleValidationError
from app.tokenize import make_token_fn

TOKEN_FN = make_token_fn("test-secret")


def make_rules(raw):
    return validate_rules(raw)


class TestValidateRules(unittest.TestCase):
    def test_valid(self):
        rules = make_rules(
            [
                {"id": "r1", "path": "$.a", "action": "delete"},
                {"id": "r2", "path": "$.b", "action": "mask", "params": {"keep_last": 2}},
                {"id": "r3", "path": "$.c[*]", "action": "tokenize"},
            ]
        )
        self.assertEqual([r.id for r in rules], ["r1", "r2", "r3"])

    def test_invalid(self):
        bad_sets = [
            [{"id": "r1", "path": "a.b", "action": "delete"}],          # no $
            [{"id": "r1", "path": "$.a", "action": "encrypt"}],          # bad action
            [{"id": "r 1", "path": "$.a", "action": "delete"}],          # bad id
            [{"id": "r1", "path": "$.a", "action": "delete"},
             {"id": "r1", "path": "$.b", "action": "delete"}],           # dup id
            [{"id": "r1", "path": "$.a", "action": "delete", "params": {"x": 1}}],
            [{"id": "r1", "path": "$.a", "action": "mask", "params": {"keep_first": -1}}],
            [{"id": "r1", "path": "$.a", "action": "mask", "params": {"mask_char": "**"}}],
            [{"id": "r1", "path": "$.a", "action": "mask", "params": {"bogus": 1}}],
        ]
        for raw in bad_sets:
            with self.assertRaises(RuleValidationError, msg=f"rules={raw!r}"):
                validate_rules(raw)


class TestApplyRules(unittest.TestCase):
    def trace_status(self, trace, rule_id, path):
        for entry in trace:
            if entry["rule_id"] == rule_id and entry["path"] == path:
                return entry["status"]
        return None

    def test_delete_object_key(self):
        doc = {"secret": "x", "keep": 1}
        rules = make_rules([{"id": "r1", "path": "$.secret", "action": "delete"}])
        result, trace = apply_rules(doc, rules, TOKEN_FN)
        self.assertEqual(result, {"keep": 1})
        self.assertEqual(self.trace_status(trace, "r1", "$.secret"), "applied")
        self.assertEqual(doc["secret"], "x")  # input not mutated

    def test_array_delete_descending(self):
        doc = {"a": [10, 20, 30, 40]}
        rules = make_rules(
            [
                {"id": "r1", "path": "$.a[1]", "action": "delete"},
                {"id": "r2", "path": "$.a[3]", "action": "delete"},
            ]
        )
        result, trace = apply_rules(doc, rules, TOKEN_FN)
        self.assertEqual(result, {"a": [10, 30]})
        self.assertEqual(self.trace_status(trace, "r1", "$.a[1]"), "applied")
        self.assertEqual(self.trace_status(trace, "r2", "$.a[3]"), "applied")

    def test_first_rule_wins_same_node(self):
        doc = {"v": "abcdef"}
        rules = make_rules(
            [
                {"id": "r1", "path": "$.v", "action": "mask", "params": {"keep_last": 2}},
                {"id": "r2", "path": "$.v", "action": "delete"},
            ]
        )
        result, trace = apply_rules(doc, rules, TOKEN_FN)
        self.assertEqual(result, {"v": "****ef"})
        self.assertEqual(self.trace_status(trace, "r1", "$.v"), "applied")
        self.assertEqual(self.trace_status(trace, "r2", "$.v"), "shadowed")

    def test_ancestor_delete_skips_descendants(self):
        doc = {"user": {"name": "ann", "ssn": "111-22-3333"}, "other": "x"}
        rules = make_rules(
            [
                {"id": "r1", "path": "$.user", "action": "delete"},
                {"id": "r2", "path": "$.user.ssn", "action": "tokenize"},
                {"id": "r3", "path": "$.other", "action": "mask"},
            ]
        )
        result, trace = apply_rules(doc, rules, TOKEN_FN)
        self.assertEqual(result, {"other": "*"})
        self.assertEqual(self.trace_status(trace, "r1", "$.user"), "applied")
        self.assertEqual(self.trace_status(trace, "r2", "$.user.ssn"), "skipped")
        entry = [e for e in trace if e["rule_id"] == "r2"][0]
        self.assertEqual(entry["reason"], "ancestor_deleted")

    def test_mask_partial(self):
        doc = {"card": "4111111111111111", "short": "ab", "num": 12345}
        rules = make_rules(
            [
                {"id": "r1", "path": "$.card", "action": "mask", "params": {"keep_last": 4}},
                {"id": "r2", "path": "$.short", "action": "mask", "params": {"keep_first": 1, "keep_last": 1}},
                {"id": "r3", "path": "$.num", "action": "mask"},
            ]
        )
        result, _ = apply_rules(doc, rules, TOKEN_FN)
        self.assertEqual(result["card"], "************1111")
        self.assertEqual(result["short"], "**")  # fully masked when too short
        self.assertEqual(result["num"], "******")

    def test_tokenize_deterministic(self):
        doc = {"ssn": "111-22-3333", "again": "111-22-3333"}
        rules = make_rules(
            [
                {"id": "r1", "path": "$.ssn", "action": "tokenize"},
                {"id": "r2", "path": "$.again", "action": "tokenize"},
            ]
        )
        result, _ = apply_rules(doc, rules, TOKEN_FN)
        self.assertTrue(result["ssn"].startswith("tok_"))
        self.assertEqual(result["ssn"], result["again"])  # deterministic
        # different key -> different token
        other = apply_rules(doc, rules, make_token_fn("other-secret"))[0]
        self.assertNotEqual(result["ssn"], other["ssn"])

    def test_wildcard_and_index_overlap(self):
        doc = {"a": ["x", "y", "z"]}
        rules = make_rules(
            [
                {"id": "r1", "path": "$.a[2]", "action": "mask"},
                {"id": "r2", "path": "$.a[*]", "action": "delete"},
            ]
        )
        result, trace = apply_rules(doc, rules, TOKEN_FN)
        # a[2] masked by r1 (first declared); a[0], a[1] deleted by r2;
        # r2's hit on a[2] is shadowed.
        self.assertEqual(result, {"a": ["*"]})
        self.assertEqual(self.trace_status(trace, "r1", "$.a[2]"), "applied")
        self.assertEqual(self.trace_status(trace, "r2", "$.a[0]"), "applied")
        self.assertEqual(self.trace_status(trace, "r2", "$.a[1]"), "applied")
        self.assertEqual(self.trace_status(trace, "r2", "$.a[2]"), "shadowed")

    def test_no_match_trace(self):
        doc = {"a": 1}
        rules = make_rules([{"id": "r1", "path": "$.nope", "action": "delete"}])
        result, trace = apply_rules(doc, rules, TOKEN_FN)
        self.assertEqual(result, {"a": 1})
        self.assertEqual(trace[0]["status"], "no_match")
        self.assertIsNone(trace[0]["path"])

    def test_mask_unsupported_target_skipped(self):
        doc = {"obj": {"a": 1}}
        rules = make_rules([{"id": "r1", "path": "$.obj", "action": "mask"}])
        result, trace = apply_rules(doc, rules, TOKEN_FN)
        self.assertEqual(result, {"obj": {"a": 1}})
        self.assertEqual(trace[0]["status"], "skipped")
        self.assertEqual(trace[0]["reason"], "unsupported_target_type")


if __name__ == "__main__":
    unittest.main()
