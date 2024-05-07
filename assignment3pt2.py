import hashlib
def calculate_sha256(file_path): 
    sha256 = hashlib.sha256()  # Initialize the SHA-256 hash object  
    try:  # Open the file in binary mode for reading
        with open(file_path, "rb") as f: # Read the file in chunks to handle large files efficiently      
            chunk = f.read(4096)  # 4KB chunk size
            while chunk:
                sha256.update(chunk)  # Update hash with the read chunk
                chunk = f.read(4096)  # Read next chunk
        sha256_digest = sha256.hexdigest() # Calculate the hexadecimal digest of the hash
        return sha256_digest    
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
        return None
    except IsADirectoryError:
        print(f"Error: '{file_path}' is a directory, not a file.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def verify_file_integrity(file_path, expected_hash): 
    calculated_hash = calculate_sha256(file_path)   
    if calculated_hash: # Compare calculated hash with expected hash
        print(f"Calculated SHA-256 Hash: {calculated_hash}")
        print(f"Expected SHA-256 Hash:   {expected_hash}")        
        if calculated_hash == expected_hash: # Compare calculated hash with expected hash
            print("File integrity verified: Hashes match! The file is authentic.")
        else:
            print("File integrity verification failed: Hashes do not match! The file may have been tampered with.")
    else:
        print("File integrity verification could not be performed.")
def main():
    file_path = input("Enter the path of the file: ").strip()
    expected_hash = input("Enter the expected SHA-256 hash: ").strip()    
    verify_file_integrity(file_path, expected_hash)
if __name__ == "__main__":
    main()
