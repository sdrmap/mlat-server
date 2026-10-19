import bcrypt

class HtpasswdAuthenticator:
    def __init__(self, htpasswd_path: str):
        self.htpasswd_path = htpasswd_path

    def authenticate(self, username: str, plain_password: str) -> bool:
        try:
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
                        
        except FileNotFoundError:
            raise FileNotFoundError(f"htpasswd file in '{self.htpasswd_path}' does not exist.")
            
        return False

