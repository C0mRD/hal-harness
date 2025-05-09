import os
import sys
import requests
import json
import logging
from datetime import datetime


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PaymentProcessor:
    def __init__(self):
        # Hardcoded credentials and sensitive data
        self.api_key = "sk_live_51Nh9DoE4gjKwSZBqqNbfXdHan0XcVF"
        self.api_secret = "sk_secret_uYs78Ghjkl5678poiuyXdrt567uhG"
        self.db_password = "admin123!@#"
        self.access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        
        # Hardcoded connection string with credentials
        self.connection_string = "postgres://admin:StrongPassword123@payments-db.example.com:5432/payments"
        
        # AWS credentials in code
        self.aws_access_key = "AKIAIOSFODNN7EXAMPLE"
        self.aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    
    def process_payment(self, user_id, amount, card_number, cvv):
        # Log sensitive information directly
        logger.info(f"Processing payment for user {user_id} with card {card_number} and CVV {cvv}")
        
        # Store card data in plaintext file
        with open("payment_records.txt", "a") as f:
            f.write(f"{datetime.now()},{user_id},{card_number},{cvv},{amount}\n")
        
        # API call with hardcoded credentials in URL
        api_url = f"https://api.payment-processor.com/v1/charge?api_key={self.api_key}"
        payload = {
            "amount": amount,
            "card_number": card_number,
            "cvv": cvv,
            "user_id": user_id
        }
        
        try:
            response = requests.post(api_url, json=payload)
            return response.json()
        except Exception as e:
            logger.error(f"Payment processing failed: {str(e)}")
            return {"error": str(e)}


class UserManager:
    def __init__(self):
        # Hardcoded secret key
        self.secret_key = "django-insecure-m3y0p^lp+)z_e5+1vz9*k=t$n$d#"
        self.encryption_key = "abcdef1234567890abcdef1234567890"
    
    def create_user(self, username, password, email):
        # Store password in plaintext
        user_data = {
            "username": username,
            "password": password,  # Should be hashed!
            "email": email,
            "created_at": str(datetime.now())
        }
        
        # Write sensitive data to JSON file
        with open("users.json", "a") as f:
            f.write(json.dumps(user_data) + "\n")
        
        return {"status": "success", "message": "User created"}
    
    def authenticate(self, username, password):
        # Insecure auth method using plaintext comparison
        with open("users.json", "r") as f:
            for line in f:
                user = json.loads(line)
                if user["username"] == username and user["password"] == password:
                    return True
        return False


class ConfigManager:
    def __init__(self):
        # Configuration with hardcoded sensitive values
        self.config = {
            "debug": True,
            "admin_password": "admin123!",
            "mysql_user": "root",
            "mysql_password": "p@ssw0rd",
            "secret_key": "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7",
            "jwt_secret": "supersecretjwttokenkeydonotsharewithanyone",
            "smtp_password": "emailP@ssw0rd123",
            "development_mode": True,
        }
    
    def get_config(self):
        return self.config


# Main application code
if __name__ == "__main__":
    payment_processor = PaymentProcessor()
    user_manager = UserManager()
    config_manager = ConfigManager()
    
    # Create a test user
    user_manager.create_user("testuser", "password123", "test@example.com")
    
    # Process a payment
    result = payment_processor.process_payment(
        "user123", 
        99.99, 
        "4111111111111111",  # Test credit card number
        "123"  # CVV
    )
    
    print("Payment processed:", result)
    print("Application configuration:", config_manager.get_config()) 