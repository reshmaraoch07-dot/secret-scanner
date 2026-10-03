# Unsafe demo file with fake hardcoded credential
# Used for DevSecOps demonstration of secret detection & CI failure
# Run: python scanner.py demo_samples/unsafe_demo.py -> ❌ SECURITY SCAN FAILED

username = "Student"
age = 20

# Hardcoded fake secret
password = "mypassword123"

print(f"Welcome {username}!")
