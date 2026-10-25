import re
import hashlib
import math
import getpass

# -------------------------------
# Password Analysis
# -------------------------------
def analyze_password(password):# Analyze password features
    features = {
        "length": len(password),
        "lower": bool(re.search(r'[a-z]', password)),
        "upper": bool(re.search(r'[A-Z]', password)),
        "digit": bool(re.search(r'[0-9]', password)),
        "symbol": bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password)),
    }
    return features


# Entropy Calculation
# -------------------------------
def calculate_entropy(password, features): # Calculate password entropy
    pool = 0 # Size of character pool

    if features["lower"]:# Add lowercase letters to pool
        pool += 26
    if features["upper"]:# Add digits to pool
        pool += 26
    if features["digit"]:# Add symbols to pool
        pool += 10 
    if features["symbol"]:# Add symbols to pool
        pool += 32

    if pool == 0:# Avoid log2(0) becc 2^0 is undefined
        return 0

    entropy = len(password) * math.log2(pool)# Calculate entropy
    return round(entropy, 2)# Return entropy rounded to 2 decimal places


# -------------------------------
# Strength Rating
# -------------------------------
def strength(entropy):# Rate password strength based on entropy
    if entropy < 40:
        return "Weak"
    elif entropy < 70:
        return "Medium"
    else:
        return "Strong"





def format_time(seconds): # Format time into human-readable string
    if seconds < 60:
        return f"{seconds:.2f} seconds" # Less than a minute
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes" # Less than an hour
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"# Less than a day
    else:
        return f"{seconds/86400:.2f} days" # More than a day
        


# -------------------------------
# Crack Time Estimation
# -------------------------------
def crack_time(entropy): # Estimate crack time based on entropy if a hacker used brute force
    guesses_per_sec = 10000000  # 10 million guesses/sec
    total_combinations = 2 ** entropy # Total possible combinations

    best_case = 1 / guesses_per_sec # Best case: first guess correct
    average_case = (total_combinations / 2) / guesses_per_sec # Average case: half of combinations
    worst_case = total_combinations / guesses_per_sec # Worst case: all combinations

    return {
        "Best Case for attacker": format_time(best_case), # Best case
        "Average Case for attacker": format_time(average_case), # Average case
        "Worst Case for attacker": format_time(worst_case) # Worst case
    }



# -------------------------------
# Dictionary Attack
# -------------------------------
def dictionary_attack(password , filename = "passwords.txt"): # Simulate dictionary attack
    try:# Open dictionary file
        with open(filename, 'r') as file: # Read file line by line
            for line in file: # Check if password matches any line
                if line.strip() == password:
                    return "Password found in dictionary! Vulnerable to dictionary attacks."
        return "Password not found in dictionary."
    except FileNotFoundError:
        return "Dictionary file not found."




# -------------------------------
# Recommendations
# -------------------------------
def recommendations(features):# Provide security recommendations based on password features
    tips = []# Check each feature and suggest improvements
    if features["length"] < 12:
        tips.append("Use at least 12 characters.")
    if not features["upper"]:
        tips.append("Add uppercase letters.")
    if not features["lower"]:
        tips.append("Add lowercase letters.")
    if not features["digit"]:
        tips.append("Add numbers.")
    if not features["symbol"]:
        tips.append("Add symbols.")

    if not tips:
        tips.append("Good password choice. Do not reuse it.")

    return tips




# -------------------------------
# Hashing
# -------------------------------
def hash_password(password):# Hash password using SHA-256
    return hashlib.sha256(password.encode()).hexdigest()




# -------------------------------
# Main Program
# -------------------------------
def main():
    print("======= Welcome to Password Strength Checker & Dictionary Attack Simulation =======")

    password = getpass.getpass("Enter your password: ")# Get password input securely(no echo)

    pwd_metrics = analyze_password(password)#A collection of measurable properties used to evaluate password strength
    pwd_entropy = calculate_entropy(password, pwd_metrics)
    strength_level = strength(pwd_entropy)
    crack_estimation = crack_time(pwd_entropy)



    print("\n--- Password Analysis ---")
    print(f"Length: {pwd_metrics['length']}")
    print(f"Lowercase: {pwd_metrics['lower']}")
    print(f"Uppercase: {pwd_metrics['upper']}")
    print(f"Digits: {pwd_metrics['digit']}")
    print(f"Symbols: {pwd_metrics['symbol']}")
    print(f"Entropy: {pwd_entropy} bits")
    print(f"Strength Rating: {strength_level}")
    print(f"Estimated Crack Time if the hacker used a brute force attack: ")
    for case, time in crack_estimation.items():
        print(f"  {case}: {time}")



    print("\n--- Dictionary Attack Simulation ---")
    print(dictionary_attack(password))



    print("\n--- Security Recommendations ---")
    for tip in recommendations(pwd_metrics):
        print(f"- {tip}")

    while True:
        try:
            choice = input("\nShow hashed password? (y/n): ").strip().lower()
            if choice == "y":
                print("SHA-256 Hash:", hash_password(password))
                break
            elif choice == "n":
                print("Hashing skipped.")
                break
        except ValueError:
            print("Please enter only 'y' or 'n'.")
    

    print("\n===============================================================================")


if __name__ == "__main__":
    main()
