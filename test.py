#!/usr/bin/env python3
# SPDX-License-Identifier: Unlicense

import unittest
import encrypt

class TestCrypto(unittest.TestCase):
    def test_encrypt(self):
        the_file_contents = "This is a test file 12 34 55"
        the_password = "hello umbc!"
        the_file_path = "test-file-1.txt"
        the_file_path_encrypted = "test-file-1.enc"
        with open(the_file_path, "w") as file:
            file.write(the_file_contents)

        encrypt.encrypt_to_file(the_file_path, the_file_path_encrypted, the_password)
        encrypt.decrypt_to_file(the_file_path, the_file_path_encrypted, the_password)

        with open(the_file_path, "r") as file:
            data = file.read()
        self.assertEqual(data, the_file_contents)

    def test_encrypt_wrong_password(self):
        the_file_contents = "This is a test file 12 34 55"
        the_file_path = "test-file-2.txt"
        the_file_path_encrypted = "test-file-2.enc"
        with open(the_file_path, "w") as file:
            file.write(the_file_contents)

        encrypt.encrypt_to_file(the_file_path, the_file_path_encrypted, "hello umbc!")
        encrypt.decrypt_to_file(the_file_path, the_file_path_encrypted, "umbc")

        with open(the_file_path, "rb") as file:
            data = file.read()
        self.assertNotEqual(data, the_file_contents.encode())


if __name__ == '__main__':
    unittest.main()