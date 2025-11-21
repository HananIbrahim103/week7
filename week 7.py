import bcrypt

def hash_password(password):
    #Encode the password to bytes required by bcrypt (unicode 8  byte)
    password_bytes = password.encode('utf-8')
    #Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    #Decode the hash back to a strig to store in a text file
    return hashed_password.decode('utf-8')

def verify_password(password, hashed_password):
    #Encode both the plaintext password and stored hash to bytes
    password_bytes = password.encode('utf-8')
    hashed_password_bytes = hashed_password.encode('utf-8')
    #bycrypt.checkpw handles extracting the salt and comparing
    return bcrypt.checkpw(password_bytes, hashed_password_bytes)

def register_user(username, password):
    with open("users.txt", "r") as f:
        for line in f.readlines():
            user, hashed_password = line.strip().split(",", 1)
            if user == username:
                print("User already registered")
                return False
            else:
                hashed_password = hash_password(password)
                with open("users.txt", "a") as file:
                    file.write(f"{username},{hashed_password}\n")
                print(f"User {username} registered")
                return True
        return False

def login_user(username, password):
    with open("users.txt", "r") as f:
        for line in f.readlines():
            user, hashed_password = line.strip().split(",", 1)
            if user == username:
                if verify_password(password, hashed_password):
                    print("User Logged in")
                    return True
                else:
                    print("Incorrect password or username. Try again")
                    return False
    return False

# TEMPORARY TEST CODE - Remove after testing
'''test_password = "SecurePassword123"
# Test hashing
hashed = hash_password(test_password)
print(f"Original password: {test_password}")
print(f"Hashed password: {hashed}")
print(f"Hash length: {len(hashed)} characters")
# Test verification with correct password
is_valid = verify_password(test_password, hashed)
print(f"\nVerification with correct password: {is_valid}")
# Test verification with incorrect password
is_invalid = verify_password("WrongPassword", hashed)
print(f"Verification with incorrect password: {is_invalid}")'''


register_user(username="admin", password="admin123")