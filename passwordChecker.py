import bcrypt

# Manually define the stored hash
stored_hash = b'$2b$12$aaNq5SSwfCB8mTTLDtoVwObvNz7m/KEEkKP0K.0ujKcKVqax6F6yy'

# The password you're testing
password = b'password1'

# Check if the password matches the stored hash
if bcrypt.checkpw(password, stored_hash):
    print("Password check passed")
else:
    print("Password check failed")
