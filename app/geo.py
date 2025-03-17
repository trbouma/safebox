import struct
import math
import bech32
from bech32 import convertbits

def encode_gps_to_hex(latitude: float, longitude: float) -> str:
    """
    Encodes a GPS coordinate (latitude, longitude) into a 32-byte hex string.
    
    :param latitude: Latitude of the GPS coordinate
    :param longitude: Longitude of the GPS coordinate
    :return: 64-character hex string (32 bytes)
    """
    # Pack latitude and longitude into bytes (each 8 bytes, total 16 bytes)
    lat_bytes = struct.pack('>d', latitude)
    lon_bytes = struct.pack('>d', longitude)
    
    # Concatenate the bytes (16 bytes total)
    combined_bytes = lat_bytes + lon_bytes
    
    # Convert to hexadecimal string (32 bytes -> 64 hex characters)
    hex_string = combined_bytes.hex()
    
    return hex_string

def decode_gps_from_hex(hex_string: str) -> tuple:
    """
    Decodes a 32-byte hex string back into a GPS coordinate (latitude, longitude).
    
    :param hex_string: 64-character hex string representing the GPS coordinate
    :return: Tuple (latitude, longitude)
    """
    # Convert hex string back to bytes
    combined_bytes = bytes.fromhex(hex_string)
    
    # Extract latitude and longitude (each 8 bytes)
    latitude = struct.unpack('>d', combined_bytes[:8])[0]
    longitude = struct.unpack('>d', combined_bytes[8:])[0]
    
    return latitude, longitude

def haversine_distance(hex1: str, hex2: str) -> float:
    """
    Calculates the great-circle distance between two GPS coordinates encoded in 32-byte hex strings.
    
    :param hex1: First 32-byte hex encoded GPS coordinate
    :param hex2: Second 32-byte hex encoded GPS coordinate
    :return: Distance in kilometers
    """
    # Decode hex strings to get latitude and longitude
    lat1, lon1 = decode_gps_from_hex(hex1)
    lat2, lon2 = decode_gps_from_hex(hex2)
    
    # Convert latitude and longitude from degrees to radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    # Radius of the Earth in kilometers
    R = 6371.0
    distance = R * c
    
    return distance

if __name__ == "__main__":
    # Example usage


    hex1 = encode_gps_to_hex(45, -75)
    hex2 = encode_gps_to_hex(46.00005, -75.00005)
    print(f"position 1: {hex1}, position 2: {hex2}")
    distance_km = haversine_distance(hex1, hex2)
    print(f"Distance: {distance_km:.3f} km")

    # converted_data = convertbits(hex2.encode(), 8, 5, True)
    # print(bech32.bech32_encode('nloc',converted_data))

   
