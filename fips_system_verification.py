#!/usr/bin/env python3
"""
FIPS 140-3 System Compliance Verification Script
This script verifies that a system with implemented FIPS 140-3 is actually
using FIPS-validated cryptographic modules and operating in FIPS mode.
"""

import os
import sys
import subprocess
import json
import hashlib
import ssl
import platform
from datetime import datetime
from pathlib import Path
import re

class FIPSSystemVerifier:
    def __init__(self):
        self.verification_results = []
        self.start_time = datetime.now()
        self.system_info = self.gather_system_info()
        
    def log_verification(self, test_name, status, details="", recommendation=""):
        """Log verification results"""
        self.verification_results.append({
            'test_name': test_name,
            'status': status,
            'details': details,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat()
        })
        
    def gather_system_info(self):
        """Gather basic system information"""
        return {
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': sys.version
        }
    
    def check_kernel_fips_mode(self):
        """Check if kernel is running in FIPS mode"""
        print("Checking Kernel FIPS Mode...")
        
        fips_files = [
            '/proc/sys/crypto/fips_enabled',
            '/sys/module/fips/parameters/fips_enabled'
        ]
        
        fips_enabled = False
        fips_details = []
        
        for fips_file in fips_files:
            try:
                if os.path.exists(fips_file):
                    with open(fips_file, 'r') as f:
                        value = f.read().strip()
                        fips_details.append(f"{fips_file}: {value}")
                        if value == '1':
                            fips_enabled = True
            except PermissionError:
                fips_details.append(f"{fips_file}: Permission denied")
            except Exception as e:
                fips_details.append(f"{fips_file}: Error - {str(e)}")
        
        if fips_enabled:
            self.log_verification("Kernel FIPS Mode", "ENABLED", 
                                "; ".join(fips_details),
                                "System is correctly running in FIPS mode")
        else:
            self.log_verification("Kernel FIPS Mode", "DISABLED", 
                                "; ".join(fips_details) if fips_details else "FIPS mode indicators not found",
                                "Enable FIPS mode: 'fips=1' kernel parameter or system configuration")
    
    def check_openssl_fips(self):
        """Check OpenSSL FIPS configuration"""
        print("Checking OpenSSL FIPS Configuration...")
        
        try:
            # Check OpenSSL version and FIPS capability
            result = subprocess.run(['openssl', 'version', '-a'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                version_info = result.stdout
                
                # Check for FIPS in version output
                if 'fips' in version_info.lower() or 'FIPS' in version_info:
                    self.log_verification("OpenSSL FIPS", "ENABLED", 
                                        f"OpenSSL FIPS capability detected: {version_info.strip()}",
                                        "OpenSSL appears to have FIPS support")
                else:
                    self.log_verification("OpenSSL FIPS", "NOT_DETECTED", 
                                        f"OpenSSL version: {version_info.strip()}",
                                        "Install FIPS-validated OpenSSL or enable FIPS mode")
            else:
                self.log_verification("OpenSSL FIPS", "ERROR", 
                                    f"Failed to check OpenSSL: {result.stderr}",
                                    "Ensure OpenSSL is installed and accessible")
                
        except subprocess.TimeoutExpired:
            self.log_verification("OpenSSL FIPS", "TIMEOUT", 
                                "OpenSSL command timed out",
                                "Check OpenSSL installation")
        except FileNotFoundError:
            self.log_verification("OpenSSL FIPS", "NOT_FOUND", 
                                "OpenSSL not found in PATH",
                                "Install OpenSSL")
        except Exception as e:
            self.log_verification("OpenSSL FIPS", "ERROR", str(e))
    
    def check_openssl_fips_providers(self):
        """Check OpenSSL FIPS providers (OpenSSL 3.0+)"""
        print("Checking OpenSSL FIPS Providers...")
        
        try:
            # List available providers
            result = subprocess.run(['openssl', 'list', '-providers'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                providers = result.stdout
                
                if 'fips' in providers.lower():
                    self.log_verification("OpenSSL FIPS Provider", "AVAILABLE", 
                                        f"FIPS provider detected in: {providers.strip()}",
                                        "FIPS provider is available")
                else:
                    self.log_verification("OpenSSL FIPS Provider", "NOT_AVAILABLE", 
                                        f"Available providers: {providers.strip()}",
                                        "Configure FIPS provider in OpenSSL")
            else:
                # Try alternative command for older versions
                result = subprocess.run(['openssl', 'list', '-cipher-algorithms'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    self.log_verification("OpenSSL FIPS Provider", "LEGACY_CHECK", 
                                        "Using legacy OpenSSL version",
                                        "Consider upgrading to OpenSSL 3.0+ for better FIPS support")
                
        except Exception as e:
            self.log_verification("OpenSSL FIPS Provider", "ERROR", str(e))
    
    def check_python_ssl_fips(self):
        """Check Python SSL module FIPS configuration"""
        print("Checking Python SSL FIPS Configuration...")
        
        try:
            # Check if Python's SSL module reports FIPS mode
            ssl_version = ssl.OPENSSL_VERSION
            ssl_version_info = ssl.OPENSSL_VERSION_INFO
            
            details = f"SSL Version: {ssl_version}, Version Info: {ssl_version_info}"
            
            # Check for FIPS in SSL version string
            if 'fips' in ssl_version.lower():
                self.log_verification("Python SSL FIPS", "ENABLED", 
                                    details,
                                    "Python SSL module has FIPS support")
            else:
                self.log_verification("Python SSL FIPS", "NOT_DETECTED", 
                                    details,
                                    "Python may not be using FIPS-enabled OpenSSL")
                
            # Try to access FIPS mode (if available)
            try:
                # This is a hypothetical check - actual implementation varies
                import _ssl
                if hasattr(_ssl, 'FIPS_mode'):
                    fips_mode = _ssl.FIPS_mode()
                    if fips_mode:
                        self.log_verification("Python SSL FIPS Mode", "ACTIVE", 
                                            f"FIPS mode is active: {fips_mode}")
                    else:
                        self.log_verification("Python SSL FIPS Mode", "INACTIVE", 
                                            "FIPS mode is not active")
                else:
                    self.log_verification("Python SSL FIPS Mode", "NOT_AVAILABLE", 
                                        "FIPS mode function not available")
            except Exception:
                self.log_verification("Python SSL FIPS Mode", "CHECK_FAILED", 
                                    "Could not check FIPS mode status")
                
        except Exception as e:
            self.log_verification("Python SSL FIPS", "ERROR", str(e))
    
    def check_cryptographic_libraries(self):
        """Check installed cryptographic libraries for FIPS support"""
        print("Checking Cryptographic Libraries...")
        
        libraries_to_check = [
            ('cryptography', 'from cryptography.fernet import Fernet'),
            ('pycryptodome', 'from Crypto.Cipher import AES'),
            ('pyopenssl', 'import OpenSSL'),
            ('hashlib', 'import hashlib')
        ]
        
        for lib_name, import_statement in libraries_to_check:
            try:
                exec(import_statement)
                
                # Special checks for specific libraries
                if lib_name == 'cryptography':
                    try:
                        from cryptography.hazmat.backends import default_backend
                        backend = default_backend()
                        backend_name = backend.name if hasattr(backend, 'name') else str(type(backend))
                        
                        self.log_verification(f"Library - {lib_name}", "AVAILABLE", 
                                            f"Backend: {backend_name}",
                                            "Verify backend is FIPS-validated")
                    except Exception as e:
                        self.log_verification(f"Library - {lib_name}", "AVAILABLE", 
                                            f"Import successful but backend check failed: {str(e)}")
                
                elif lib_name == 'hashlib':
                    # Check if hashlib algorithms are using OpenSSL
                    try:
                        algorithms = hashlib.algorithms_available
                        openssl_algos = getattr(hashlib, 'algorithms_guaranteed', set())
                        
                        self.log_verification(f"Library - {lib_name}", "AVAILABLE", 
                                            f"Available algorithms: {len(algorithms)}, Guaranteed: {len(openssl_algos)}",
                                            "Ensure using FIPS-validated implementations")
                    except Exception:
                        self.log_verification(f"Library - {lib_name}", "AVAILABLE", 
                                            "Basic import successful")
                else:
                    self.log_verification(f"Library - {lib_name}", "AVAILABLE", 
                                        "Library imported successfully",
                                        "Verify library uses FIPS-validated modules")
                    
            except ImportError:
                self.log_verification(f"Library - {lib_name}", "NOT_AVAILABLE", 
                                    "Library not installed")
            except Exception as e:
                self.log_verification(f"Library - {lib_name}", "ERROR", str(e))
    
    def check_fips_configuration_files(self):
        """Check for FIPS configuration files"""
        print("Checking FIPS Configuration Files...")
        
        config_locations = [
            '/etc/crypto-policies/config',
            '/etc/system-fips',
            '/etc/openssl/fipsmodule.cnf',
            '/usr/local/ssl/fipsmodule.cnf',
            '/etc/ssl/fipsmodule.cnf'
        ]
        
        found_configs = []
        
        for config_path in config_locations:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        content = f.read()
                        found_configs.append(f"{config_path}: {len(content)} bytes")
                        
                        # Check for FIPS-related content
                        if 'fips' in content.lower() or 'FIPS' in content:
                            self.log_verification("FIPS Config File", "FOUND", 
                                                f"FIPS configuration detected in {config_path}")
                except PermissionError:
                    found_configs.append(f"{config_path}: Permission denied")
                except Exception as e:
                    found_configs.append(f"{config_path}: Error reading - {str(e)}")
        
        if found_configs:
            self.log_verification("FIPS Configuration Files", "FOUND", 
                                "; ".join(found_configs),
                                "Review configuration files for proper FIPS settings")
        else:
            self.log_verification("FIPS Configuration Files", "NOT_FOUND", 
                                "No FIPS configuration files found in standard locations",
                                "Check if FIPS configuration is needed for your setup")
    
    def test_actual_fips_behavior(self):
        """Test if cryptographic operations actually use FIPS modules"""
        print("Testing Actual FIPS Behavior...")
        
        try:
            # Test if non-FIPS algorithms are rejected
            test_cases = [
                {
                    'name': 'MD5 Hash (should be rejected in FIPS mode)',
                    'test': lambda: hashlib.md5(b'test').hexdigest(),
                    'expect_failure': True
                },
                {
                    'name': 'SHA1 Hash (may be rejected in strict FIPS mode)',
                    'test': lambda: hashlib.sha1(b'test').hexdigest(),
                    'expect_failure': False  # SHA1 might be allowed for some uses
                },
                {
                    'name': 'SHA256 Hash (should work in FIPS mode)',
                    'test': lambda: hashlib.sha256(b'test').hexdigest(),
                    'expect_failure': False
                }
            ]
            
            for test_case in test_cases:
                try:
                    result = test_case['test']()
                    if test_case['expect_failure']:
                        self.log_verification(f"FIPS Behavior - {test_case['name']}", "WARNING", 
                                            f"Non-FIPS algorithm executed successfully: {result[:16]}...",
                                            "System may not be enforcing FIPS mode strictly")
                    else:
                        self.log_verification(f"FIPS Behavior - {test_case['name']}", "PASS", 
                                            f"FIPS-approved algorithm executed: {result[:16]}...")
                except Exception as e:
                    if test_case['expect_failure']:
                        self.log_verification(f"FIPS Behavior - {test_case['name']}", "PASS", 
                                            f"Non-FIPS algorithm properly rejected: {str(e)}",
                                            "Good - FIPS mode is enforcing algorithm restrictions")
                    else:
                        self.log_verification(f"FIPS Behavior - {test_case['name']}", "FAIL", 
                                            f"FIPS algorithm failed: {str(e)}",
                                            "Check FIPS module configuration")
                        
        except Exception as e:
            self.log_verification("FIPS Behavior Test", "ERROR", str(e))
    
    def check_certificate_validation(self):
        """Check SSL/TLS certificate validation in FIPS mode"""
        print("Checking SSL Certificate Validation...")
        
        try:
            import ssl
            import socket
            
            # Test SSL context creation
            context = ssl.create_default_context()
            
            # Check available ciphers
            ciphers = context.get_ciphers()
            fips_compatible_ciphers = []
            
            for cipher in ciphers:
                cipher_name = cipher.get('name', '')
                # Check for FIPS-compatible ciphers (AES, not RC4, not MD5, etc.)
                if any(algo in cipher_name for algo in ['AES', 'SHA256', 'SHA384']):
                    fips_compatible_ciphers.append(cipher_name)
            
            total_ciphers = len(ciphers)
            fips_ciphers = len(fips_compatible_ciphers)
            
            self.log_verification("SSL Cipher Suite", "INFO", 
                                f"Total ciphers: {total_ciphers}, FIPS-compatible: {fips_ciphers}",
                                "Ensure only FIPS-approved ciphers are used in production")
            
        except Exception as e:
            self.log_verification("SSL Certificate Validation", "ERROR", str(e))
    
    def generate_compliance_report(self):
        """Generate comprehensive compliance verification report"""
        print("\n" + "="*70)
        print("FIPS 140-3 SYSTEM COMPLIANCE VERIFICATION REPORT")
        print("="*70)
        
        # Summary statistics
        total_checks = len(self.verification_results)
        enabled_count = len([r for r in self.verification_results if r['status'] == 'ENABLED'])
        pass_count = len([r for r in self.verification_results if r['status'] == 'PASS'])
        warning_count = len([r for r in self.verification_results if r['status'] == 'WARNING'])
        fail_count = len([r for r in self.verification_results if r['status'] == 'FAIL'])
        error_count = len([r for r in self.verification_results if r['status'] == 'ERROR'])
        
        print(f"\nSystem Information:")
        for key, value in self.system_info.items():
            print(f"  {key}: {value}")
        
        print(f"\nVerification Summary:")
        print(f"  Total Checks: {total_checks}")
        print(f"  FIPS Enabled: {enabled_count}")
        print(f"  Passed: {pass_count}")
        print(f"  Warnings: {warning_count}")
        print(f"  Failed: {fail_count}")
        print(f"  Errors: {error_count}")
        
        print(f"\nVerification Duration: {datetime.now() - self.start_time}")
        print(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Detailed results
        print("\n" + "-"*70)
        print("DETAILED VERIFICATION RESULTS")
        print("-"*70)
        
        status_symbols = {
            'ENABLED': '✓',
            'PASS': '✓',
            'WARNING': '⚠',
            'FAIL': '✗',
            'ERROR': '!',
            'NOT_AVAILABLE': '○',
            'NOT_FOUND': '○',
            'NOT_DETECTED': '○',
            'DISABLED': '✗',
            'INFO': 'ℹ'
        }
        
        for result in self.verification_results:
            symbol = status_symbols.get(result['status'], '?')
            print(f"\n{symbol} {result['test_name']}: {result['status']}")
            
            if result['details']:
                print(f"   Details: {result['details']}")
            if result['recommendation']:
                print(f"   Recommendation: {result['recommendation']}")
        
        # Overall compliance assessment
        print("\n" + "="*70)
        print("COMPLIANCE ASSESSMENT")
        print("="*70)
        
        fips_mode_enabled = any(r['status'] == 'ENABLED' and 'FIPS Mode' in r['test_name'] 
                               for r in self.verification_results)
        
        if fips_mode_enabled and fail_count == 0:
            print("✓ FIPS mode is enabled and no critical failures detected")
            print("✓ System appears to be properly configured for FIPS 140-3")
        elif fips_mode_enabled:
            print("⚠ FIPS mode is enabled but some issues were detected")
            print("⚠ Review failed checks and recommendations")
        else:
            print("✗ FIPS mode is not enabled")
            print("✗ System is not operating in FIPS 140-3 compliant mode")
        
        print("\nNext Steps:")
        print("1. Review all WARNING and FAIL items above")
        print("2. Implement recommended fixes")
        print("3. Verify cryptographic module certificates")
        print("4. Test application-specific FIPS compliance")
        print("5. Document compliance procedures")
        
        # Save detailed report
        self.save_verification_report()
    
    def save_verification_report(self):
        """Save detailed verification report as JSON"""
        report_data = {
            'verification_summary': {
                'total_checks': len(self.verification_results),
                'enabled': len([r for r in self.verification_results if r['status'] == 'ENABLED']),
                'passed': len([r for r in self.verification_results if r['status'] == 'PASS']),
                'warnings': len([r for r in self.verification_results if r['status'] == 'WARNING']),
                'failed': len([r for r in self.verification_results if r['status'] == 'FAIL']),
                'errors': len([r for r in self.verification_results if r['status'] == 'ERROR']),
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat()
            },
            'system_info': self.system_info,
            'verification_results': self.verification_results
        }
        
        filename = f"fips_system_verification_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"\n📄 Detailed verification report saved to: {filename}")
        except Exception as e:
            print(f"\n⚠ Could not save JSON report: {e}")
    
    def run_system_verification(self):
        """Execute complete system FIPS verification"""
        print("Starting FIPS 140-3 System Compliance Verification...")
        print("="*70)
        
        # Run all verification checks
        self.check_kernel_fips_mode()
        self.check_openssl_fips()
        self.check_openssl_fips_providers()
        self.check_python_ssl_fips()
        self.check_cryptographic_libraries()
        self.check_fips_configuration_files()
        self.test_actual_fips_behavior()
        self.check_certificate_validation()
        
        # Generate comprehensive report
        self.generate_compliance_report()

if __name__ == "__main__":
    print("FIPS 140-3 System Compliance Verification Tool")
    print("This tool verifies FIPS compliance on systems with implemented FIPS 140-3\n")
    
    if os.geteuid != 0:
        print("Note: Some checks may require root privileges for complete verification\n")
    
    verifier = FIPSSystemVerifier()
    verifier.run_system_verification()
