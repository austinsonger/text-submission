import jwt
import datetime

# Read the new private key from the file
private_key = open('new_jwt_ecdsa_key', 'r').read()

# Define the payload for the JWT
payload = {
    'sub': '1234567890',
    'name': 'John Doe',
    'iat': datetime.datetime.now(datetime.timezone.utc),
    'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
}

# Encode the JWT using the new private key and ES256 algorithm
token = jwt.encode(payload, private_key, algorithm='ES256')

# Print the generated JWT token
print(token)