import unittest

from app import jcs


class TestCanonicalize(unittest.TestCase):
    def test_scalars(self):
        self.assertEqual(jcs.canonicalize(None), "null")
        self.assertEqual(jcs.canonicalize(True), "true")
        self.assertEqual(jcs.canonicalize(False), "false")
        self.assertEqual(jcs.canonicalize(42), "42")
        self.assertEqual(jcs.canonicalize(-7), "-7")
        self.assertEqual(jcs.canonicalize("hi"), '"hi"')

    def test_numbers_es6_format(self):
        cases = {
            1.0: "1",
            0.1: "0.1",
            1e20: "100000000000000000000",
            1e21: "1e+21",
            1e-6: "0.000001",
            1e-7: "1e-7",
            1.5e-7: "1.5e-7",
            -0.0: "0",
            3.14159: "3.14159",
            123456789012345680000.0: "123456789012345680000",
        }
        for value, expected in cases.items():
            self.assertEqual(jcs.canonicalize(value), expected, f"value={value!r}")

    def test_object_key_ordering(self):
        doc = {"b": 1, "a": 2, "A": 3, "ä": 4}
        # sorted by UTF-16 code units: 'A'(0x41) < 'a'(0x61) < 'b'(0x62) < 'ä'(0xE4)
        self.assertEqual(
            jcs.canonicalize(doc), '{"A":3,"a":2,"b":1,"ä":4}'
        )

    def test_nested_and_arrays(self):
        doc = {"list": [1, "x", None, {"y": [True]}], "s": "a\nb\"c"}
        self.assertEqual(
            jcs.canonicalize(doc),
            '{"list":[1,"x",null,{"y":[true]}],"s":"a\\nb\\"c"}',
        )

    def test_string_escaping_control_chars(self):
        self.assertEqual(jcs.canonicalize(""), '"\\u0001"')
        self.assertEqual(jcs.canonicalize("\t\r\n"), '"\\t\\r\\n"')

    def test_lone_surrogate_rejected(self):
        with self.assertRaises(jcs.CanonicalizationError):
            jcs.canonicalize("\ud800")

    def test_digest_stable_and_order_insensitive(self):
        a = {"x": 1, "y": [1, 2, {"z": "v"}]}
        b = {"y": [1, 2, {"z": "v"}], "x": 1}
        self.assertEqual(jcs.digest(a), jcs.digest(b))
        self.assertEqual(len(jcs.digest(a)), 64)
        self.assertNotEqual(jcs.digest(a), jcs.digest({"x": 1}))


if __name__ == "__main__":
    unittest.main()
