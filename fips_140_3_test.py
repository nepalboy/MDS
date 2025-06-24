#!/usr/bin/env python3
"""
FIPS 140-3 Compliance Test Suite
This script tests various cryptographic functions for FIPS 140-3 compliance
and generates a comprehensive report.
"""

import hashlib
import hmac
import os
import sys
import json
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

class FIPS140_3_Tester:
    def __init__(self):
        self.test_results = []
        self.start_time = datetime.now()
        self.backend = default_backend()
        
    def log_test(self, test_name, status, details="", execution_time=0):
        """Log test results"""
        self.test_results.append({
            'test_name': test_name,
            'status': status,
            'details': details,
            'execution_time': execution_time,
            'timestamp': datetime.now().isoformat()
        })
        
    def test_random_number_generation(self):
        """Test FIPS-approved random number generation"""
        print("Testing Random Number Generation...")
        start_time = time.time()
        
        try:
            # Test os.urandom (should use system's CSPRNG)
            random_bytes = os.urandom(32)
            if len(random_bytes) == 32:
                self.log_test("OS Random Generation", "PASS", 
                            f"Generated {len(random_bytes)} random bytes", 
                            time.time() - start_time)
            else:
                self.log_test("OS Random Generation", "FAIL", 
                            "Failed to generate expected number of bytes")
                
            # Test secrets module (FIPS-approved)
            secure_random = secrets.token_bytes(32)
            if len(secure_random) == 32:
                self.log_test("Secrets Module", "PASS", 
                            f"Generated {len(secure_random)} secure random bytes",
                            time.time() - start_time)
            else:
                self.log_test("Secrets Module", "FAIL", 
                            "Failed to generate secure random bytes")
                
        except Exception as e:
            self.log_test("Random Number Generation", "ERROR", str(e))
    
    def test_hash_functions(self):
        """Test FIPS-approved hash functions"""
        print("Testing Hash Functions...")
        
        test_data = b"FIPS 140-3 compliance test data"
        approved_hashes = {
            'SHA-256': hashlib.sha256,
            'SHA-384': hashlib.sha384,
            'SHA-512': hashlib.sha512,
            'SHA-224': hashlib.sha224
        }
        
        for hash_name, hash_func in approved_hashes.items():
            start_time = time.time()
            try:
                digest = hash_func(test_data).hexdigest()
                self.log_test(f"Hash Function - {hash_name}", "PASS", 
                            f"Generated digest: {digest[:16]}...",
                            time.time() - start_time)
            except Exception as e:
                self.log_test(f"Hash Function - {hash_name}", "ERROR", str(e))
    
    def test_hmac(self):
        """Test HMAC with FIPS-approved hash functions"""
        print("Testing HMAC...")
        
        key = secrets.token_bytes(32)
        message = b"FIPS 140-3 HMAC test message"
        
        hmac_tests = {
            'HMAC-SHA256': hashlib.sha256,
            'HMAC-SHA384': hashlib.sha384,
            'HMAC-SHA512': hashlib.sha512
        }
        
        for hmac_name, hash_func in hmac_tests.items():
            start_time = time.time()
            try:
                mac = hmac.new(key, message, hash_func).hexdigest()
                self.log_test(f"{hmac_name}", "PASS", 
                            f"Generated MAC: {mac[:16]}...",
                            time.time() - start_time)
            except Exception as e:
                self.log_test(f"{hmac_name}", "ERROR", str(e))
    
    def test_symmetric_encryption(self):
        """Test FIPS-approved symmetric encryption algorithms"""
        print("Testing Symmetric Encryption...")
        
        # AES-256 with GCM mode (FIPS approved)
        start_time = time.time()
        try:
            key = secrets.token_bytes(32)  # 256-bit key
            iv = secrets.token_bytes(12)   # 96-bit IV for GCM
            plaintext = b"FIPS 140-3 AES encryption test data"
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Test decryption
            decryptor = Cipher(algorithms.AES(key), 
                             modes.GCM(iv, encryptor.tag), 
                             backend=self.backend).decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            if decrypted == plaintext:
                self.log_test("AES-256-GCM Encryption", "PASS", 
                            f"Encrypted/decrypted {len(plaintext)} bytes",
                            time.time() - start_time)
            else:
                self.log_test("AES-256-GCM Encryption", "FAIL", 
                            "Decryption did not match original plaintext")
                
        except Exception as e:
            self.log_test("AES-256-GCM Encryption", "ERROR", str(e))
    
    def test_asymmetric_encryption(self):
        """Test FIPS-approved asymmetric encryption"""
        print("Testing Asymmetric Encryption...")
        
        start_time = time.time()
        try:
            # Generate RSA key pair (2048-bit minimum for FIPS)
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend
            )
            public_key = private_key.public_key()
            
            # Test encryption/decryption
            message = b"FIPS 140-3 RSA test message"
            ciphertext = public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            decrypted = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            if decrypted == message:
                self.log_test("RSA-2048 Encryption", "PASS", 
                            f"RSA key pair generated and tested successfully",
                            time.time() - start_time)
            else:
                self.log_test("RSA-2048 Encryption", "FAIL", 
                            "RSA decryption failed")
                
        except Exception as e:
            self.log_test("RSA-2048 Encryption", "ERROR", str(e))
    
    def test_key_derivation(self):
        """Test FIPS-approved key derivation functions"""
        print("Testing Key Derivation Functions...")
        
        start_time = time.time()
        try:
            password = b"test_password_for_fips_compliance"
            salt = secrets.token_bytes(16)
            
            # PBKDF2 with SHA-256 (FIPS approved)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self.backend
            )
            
            derived_key = kdf.derive(password)
            
            if len(derived_key) == 32:
                self.log_test("PBKDF2-SHA256", "PASS", 
                            f"Derived {len(derived_key)}-byte key with 100,000 iterations",
                            time.time() - start_time)
            else:
                self.log_test("PBKDF2-SHA256", "FAIL", 
                            "Unexpected key length")
                
        except Exception as e:
            self.log_test("PBKDF2-SHA256", "ERROR", str(e))
    
    def test_digital_signatures(self):
        """Test FIPS-approved digital signature algorithms"""
        print("Testing Digital Signatures...")
        
        start_time = time.time()
        try:
            # Generate RSA key pair for signing
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend
            )
            public_key = private_key.public_key()
            
            message = b"FIPS 140-3 digital signature test message"
            
            # Sign with PSS padding (FIPS approved)
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Verify signature
            try:
                public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                self.log_test("RSA-PSS Digital Signature", "PASS", 
                            "Signature generated and verified successfully",
                            time.time() - start_time)
            except:
                self.log_test("RSA-PSS Digital Signature", "FAIL", 
                            "Signature verification failed")
                
        except Exception as e:
            self.log_test("RSA-PSS Digital Signature", "ERROR", str(e))
    
    def check_fips_mode(self):
        """Check if system is in FIPS mode"""
        print("Checking FIPS Mode Status...")
        
        try:
            # Check for FIPS mode indicators
            fips_indicators = [
                '/proc/sys/crypto/fips_enabled',
                '/sys/module/fips/parameters/fips_enabled'
            ]
            
            fips_enabled = False
            for indicator in fips_indicators:
                try:
                    with open(indicator, 'r') as f:
                        if f.read().strip() == '1':
                            fips_enabled = True
                            break
                except FileNotFoundError:
                    continue
            
            if fips_enabled:
                self.log_test("FIPS Mode Check", "PASS", 
                            "System is running in FIPS mode")
            else:
                self.log_test("FIPS Mode Check", "WARNING", 
                            "System is not in FIPS mode - tests show algorithm compatibility only")
                
        except Exception as e:
            self.log_test("FIPS Mode Check", "INFO", 
                        "Could not determine FIPS mode status")
    
    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "="*60)
        print("FIPS 140-3 COMPLIANCE TEST REPORT")
        print("="*60)
        
        total_tests = len(self.test_results)
        passed_tests = len([t for t in self.test_results if t['status'] == 'PASS'])
        failed_tests = len([t for t in self.test_results if t['status'] == 'FAIL'])
        error_tests = len([t for t in self.test_results if t['status'] == 'ERROR'])
        warning_tests = len([t for t in self.test_results if t['status'] == 'WARNING'])
        
        print(f"\nTest Summary:")
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Errors: {error_tests}")
        print(f"Warnings: {warning_tests}")
        
        success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        print(f"Success Rate: {success_rate:.1f}%")
        
        print(f"\nTest Duration: {datetime.now() - self.start_time}")
        print(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("\n" + "-"*60)
        print("DETAILED TEST RESULTS")
        print("-"*60)
        
        for result in self.test_results:
            status_symbol = {
                'PASS': '✓',
                'FAIL': '✗',
                'ERROR': '!',
                'WARNING': '⚠',
                'INFO': 'ℹ'
            }.get(result['status'], '?')
            
            print(f"\n{status_symbol} {result['test_name']}: {result['status']}")
            if result['details']:
                print(f"   Details: {result['details']}")
            if result['execution_time'] > 0:
                print(f"   Execution Time: {result['execution_time']:.4f}s")
        
        # Compliance assessment
        print("\n" + "="*60)
        print("COMPLIANCE ASSESSMENT")
        print("="*60)
        
        if failed_tests == 0 and error_tests == 0:
            print("✓ All cryptographic algorithms tested successfully")
            print("✓ Implementation appears FIPS 140-3 compatible")
        else:
            print("⚠ Some tests failed - review implementation")
            
        print("\nNOTE: This test verifies algorithm compatibility.")
        print("Full FIPS 140-3 compliance requires:")
        print("- Certified cryptographic module")
        print("- Proper key management")
        print("- Security policy implementation")
        print("- Physical security controls")
        print("- Official validation by accredited lab")
        
        # Save report to file
        self.save_report_json()
        
    def save_report_json(self):
        """Save detailed report as JSON"""
        report_data = {
            'test_summary': {
                'total_tests': len(self.test_results),
                'passed': len([t for t in self.test_results if t['status'] == 'PASS']),
                'failed': len([t for t in self.test_results if t['status'] == 'FAIL']),
                'errors': len([t for t in self.test_results if t['status'] == 'ERROR']),
                'warnings': len([t for t in self.test_results if t['status'] == 'WARNING']),
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat()
            },
            'test_results': self.test_results,
            'system_info': {
                'python_version': sys.version,
                'platform': sys.platform
            }
        }
        
        filename = f"fips_140_3_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"\n📄 Detailed report saved to: {filename}")
        except Exception as e:
            print(f"\n⚠ Could not save JSON report: {e}")
    
    def run_all_tests(self):
        """Execute all FIPS 140-3 compliance tests"""
        print("Starting FIPS 140-3 Compliance Test Suite...")
        print("="*60)
        
        # Run all test categories
        self.check_fips_mode()
        self.test_random_number_generation()
        self.test_hash_functions()
        self.test_hmac()
        self.test_symmetric_encryption()
        self.test_asymmetric_encryption()
        self.test_key_derivation()
        self.test_digital_signatures()
        
        # Generate final report
        self.generate_report()

if __name__ == "__main__":
    # Check for required dependencies
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        print("Error: cryptography library not found.")
        print("Install with: pip install cryptography")
        sys.exit(1)
    
    # Run the test suite
    tester = FIPS140_3_Tester()
    tester.run_all_tests()
