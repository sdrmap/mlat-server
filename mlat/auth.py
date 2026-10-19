import os
import bcrypt

class HtpasswdAuthenticator:
    def __init__(self, htpasswd_path: str):
        self.htpasswd_path = os.path.abspath(htpasswd_path)
        
        if not os.path.exists(self.htpasswd_path):
            raise FileNotFoundError(f"The htpasswd file at '{self.htpasswd_path}' does not exist.")

    def authenticate(self, username: str, plain_password: str) -> bool:
        with open(self.htpasswd_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or ':' not in line:
                    continue
                
                file_username, stored_hash = line.split(':', 1)
                
                if file_username == username:
                    password_bytes = plain_password.encode('utf-8')
                    hash_bytes = stored_hash.encode('utf-8')
                    
                    return bcrypt.checkpw(password_bytes, hash_bytes)
            
        return False

