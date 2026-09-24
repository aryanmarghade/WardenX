import math
import collections
import logging

def calculate_entropy(file_path):
    """
    Calculates the Shannon Entropy of a file.
    Higher entropy (approaching 8.0) suggests encryption, packing, or obfuscation.
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            if not data:
                return 0.0
            
            entropy = 0.0
            length = len(data)
            
            # Count frequency of each byte (0-255)
            occurrences = collections.Counter(data)
            
            for count in occurrences.values():
                probability = count / length
                entropy -= probability * math.log2(probability)
                
            return entropy
    except Exception as e:
        logging.error(f"Error calculating entropy for {file_path}: {e}")
        return 0.0
