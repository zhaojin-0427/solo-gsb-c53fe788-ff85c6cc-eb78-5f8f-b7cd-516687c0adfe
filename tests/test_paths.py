import unittest

from app.paths import (
    KIND_INDEX,
    KIND_KEY,
    KIND_WILDCARD,
    PathSyntaxError,
    find_matches,
    parse_path,
)


class TestParsePath(unittest.TestCase):
    def test_valid_paths(self):
        segs = parse_path("$.users[0].name")
        self.assertEqual(
            [(s.kind, s.value) for s in segs],
            [(KIND_KEY, "users"), (KIND_INDEX, 0), (KIND_KEY, "name")],
        )
        segs = parse_path("$.a[*].b")
        self.assertEqual(
            [(s.kind, s.value) for s in segs],
            [(KIND_KEY, "a"), (KIND_WILDCARD, None), (KIND_KEY, "b")],
        )
        segs = parse_path("$._x9[123]")
        self.assertEqual(
            [(s.kind, s.value) for s in segs],
            [(KIND_KEY, "_x9"), (KIND_INDEX, 123)],
        )

    def test_invalid_paths(self):
        for bad in [
            "",
            "users[0]",
            "$",
            "$.",
            "$.0abc",
            "$.a..b",
            "$.a[",
            "$.a[-1]",
            "$.a[1.5]",
            "$.a[x]",
            "$.a['b']",
            "$.a b",
            "$[0]x",
            "$.a[1]b",
        ]:
            with self.assertRaises(PathSyntaxError, msg=f"path={bad!r}"):
                parse_path(bad)


class TestFindMatches(unittest.TestCase):
    def setUp(self):
        self.doc = {
            "users": [
                {"name": "ann", "ssn": "111"},
                {"name": "bob", "ssn": "222"},
            ],
            "meta": {"count": 2},
        }

    def test_key_and_index(self):
        m = find_matches(self.doc, parse_path("$.users[1].ssn"))
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0].value, "222")
        self.assertEqual(m[0].path, "$.users[1].ssn")
        self.assertIs(m[0].parent, self.doc["users"][1])
        self.assertEqual(m[0].key, "ssn")

    def test_wildcard(self):
        m = find_matches(self.doc, parse_path("$.users[*].ssn"))
        self.assertEqual([x.path for x in m], ["$.users[0].ssn", "$.users[1].ssn"])
        self.assertEqual([x.value for x in m], ["111", "222"])

    def test_wildcard_on_array_root_of_match(self):
        m = find_matches(self.doc, parse_path("$.users[*]"))
        self.assertEqual(len(m), 2)
        self.assertIs(m[0].parent, self.doc["users"])
        self.assertEqual(m[1].key, 1)

    def test_no_match_cases(self):
        self.assertEqual(find_matches(self.doc, parse_path("$.missing")), [])
        self.assertEqual(find_matches(self.doc, parse_path("$.users[9]")), [])
        self.assertEqual(find_matches(self.doc, parse_path("$.meta[*]")), [])  # not a list
        self.assertEqual(find_matches(self.doc, parse_path("$.users[0].name.x")), [])


if __name__ == "__main__":
    unittest.main()
