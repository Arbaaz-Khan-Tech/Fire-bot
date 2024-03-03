import random

def check_password_strength(password):
  """
  Checks the strength of a password based on length, character types, and common patterns.

  Args:
    password: The password to check.

  Returns:
    A tuple containing:
      - A score (0-100) indicating the strength of the password.
      - A list of reasons why the password is weak (if applicable).
  """

  reasons = []
  score = 0

  # Check password length
  if len(password) < 8:
    reasons.append("Password is too short. Minimum length is 8 characters.")
  else:
    score += len(password) * 4

  # Check for character types
  has_uppercase = False
  has_lowercase = False
  has_number = False
  has_symbol = False
  for char in password:
    if char.isupper():
      has_uppercase = True
    elif char.islower():
      has_lowercase = True
    elif char.isdigit():
      has_number = True
    else:
      has_symbol = True

  if not has_uppercase:
    reasons.append("Password does not contain an uppercase letter.")
  else:
    score += 20
  if not has_lowercase:
    reasons.append("Password does not contain a lowercase letter.")
  else:
    score += 20
  if not has_number:
    reasons.append("Password does not contain a number.")
  else:
    score += 20
  if not has_symbol:
    reasons.append("Password does not contain a symbol.")
  else:
    score += 20

  # Check for common patterns
  common_patterns = ["123456", "qwertyuiop", "password", "iloveyou", "admin", "12345", "abc123"]
  for pattern in common_patterns:
    if pattern in password:
      reasons.append(f"Password contains a common pattern: {pattern}")
      score -= 20

  # Adjust score based on number of reasons
  if reasons:
    score -= len(reasons) * 10

  return score, reasons

def generate_password(username, length=12):
  """
  Generates a random password based on the username and desired length.

  Args:
    username: The username to use as a seed for password generation.
    length: The desired length of the password.

  Returns:
    A randomly generated password.
  """

  # Hash the username to avoid storing it in plain text
  username_hash = hash(username)

  # Use the hash to seed the random number generator
  random.seed(username_hash)

  # Generate password using a combination of uppercase, lowercase, numbers, and symbols
  password = ""
  for _ in range(length):
    char_type = random.choice([0, 1, 2, 3])
    if char_type == 0:
      password += chr(random.randint(65, 90))  # Uppercase letter
    elif char_type == 1:
      password += chr(random.randint(97, 122))  # Lowercase letter
    elif char_type == 2:
      password += str(random.randint(0, 9))  # Number
    else:
      password += chr(random.randint(33, 47) + random.randint(58, 64))  # Symbol

  return password

# Example usage
password = input("Enter Pass")
score, reasons = check_password_strength(password)
print(f"Password strength: {score}/100")
if reasons:
  print("Reasons for weakness:")
  for reason in reasons:
    print(f"- {reason}")
