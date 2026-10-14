"""
test_obb.py - Tests all 6 OBB test vectors.
"""

import unittest
from apkrevive.core.obb import validate_obb_delivery

OBB_VECTORS = [
    {"id": "OBB-VEC-01", "filename": "main.100.com.example.game.obb", "pkg": "com.example.game", "apk_vcode": 150, "valid": True, "warn": None},
    {"id": "OBB-VEC-02", "filename": "patch.100.com.example.game.obb", "pkg": "com.example.game", "apk_vcode": 100, "valid": True, "warn": None},
    {"id": "OBB-VEC-03", "filename": "main.100.com.example.game.obb\n", "pkg": "com.example.game", "apk_vcode": 150, "valid": False, "reason": "INVALID_OBB_FILENAME_FORMAT"},
    {"id": "OBB-VEC-04", "filename": "../../data/app/evil.obb", "pkg": "com.example.game", "apk_vcode": 100, "valid": False, "reason": "PATH_TRAVERSAL_DETECTED"},
    {"id": "OBB-VEC-05", "filename": "main.100.com.other.game.obb", "pkg": "com.example.game", "apk_vcode": 150, "valid": False, "reason": "PACKAGE_NAME_MISMATCH"},
    {"id": "OBB-VEC-06", "filename": "main.200.com.example.game.obb", "pkg": "com.example.game", "apk_vcode": 100, "valid": True, "warn": "EXPANSION_VERSION_AHEAD_OF_APK"}
]


class TestObb(unittest.TestCase):
    def test_all_6_obb_vectors(self):
        for vec in OBB_VECTORS:
            with self.subTest(vec_id=vec["id"]):
                res = validate_obb_delivery(vec["filename"], vec["pkg"], vec["apk_vcode"])
                self.assertEqual(res["valid"], vec["valid"])
                if vec.get("reason"):
                    self.assertIn(vec["reason"], res.get("reason", ""))
                if vec.get("warn"):
                    self.assertIn(vec["warn"], res.get("warning", "") or "")


if __name__ == "__main__":
    unittest.main()
