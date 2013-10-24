/*
 * Methods that support bit manipulation.
 * 
 * Since the apex language lacks a byte primitive, bytes are represented as integers within this class.  All integer values in this class
 * are treated as bytes unless otherwise noted.  You should never pass in an integer that is larger than 256 when a byte is expected.  There
 * are no checks for this condition but unpredictable results may occur if you do.
 *
 * All methods use little endian encoding unless otherwise noted.
 *
 * @author Nate Wallace
 */
public class BitConverter { 
    
    /*
     * Table of base 64 values in order.
     */
    private static string[] mBase64Table;
    
    /*
     * Mapping of base 64 values to their 6 bit equivalent.
     */
    private static Map<string, integer> mBase64To6BitMap;   
    
    /*
     * Mapping of hex digit to base 10 digit.
     */
    private static Map<string, integer> mHexMap;    
    
    /*
     * Initialize static members.
     */
    static {
        mBase64Table = new string[]{
         'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
         'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
         '0','1','2','3','4','5','6','7','8','9','+','/'};
        
        mBase64To6BitMap = new Map<string, integer>(); 
        for (integer i = 0; i < mBase64Table.size(); i++)
            mBase64To6BitMap.put(mBase64Table[i], i);   
            
        mHexMap = new Map<string, integer> {
            '0' => 0,
            '1' => 1,
            '2' => 2,
            '3' => 3,
            '4' => 4,
            '5' => 5,
            '6' => 6,
            '7' => 7,
            '8' => 8,
            '9' => 9,
            'A' => 10,
            'B' => 11,
            'C' => 12,
            'D' => 13,
            'E' => 14,
            'F' => 15,
            'a' => 10,
            'b' => 11,
            'c' => 12,
            'd' => 13,
            'e' => 14,
            'f' => 15
        };       
    }
    
    /*
     * Convert the base 64 encoded string into an array of bytes.
     *
     * @param text The base 64 encoded string to decode.
     * @return The decoded base 64 string as an array of bytes.
     */
    public static integer[] decodeBase64String(String text) {
    System.debug('hello');
        if (text == null)
            throw new RuntimeException('text is null');
        if (Math.mod(text.length(), 4) != 0)
            throw new RuntimeException('text is not a valid base 64 encoded string (not a multiple of 4).');
            
        integer[] result = new integer[]{};
        
        for (integer i= 0; i < text.length(); i += 4)
        {
            string firstChar = text.substring(i, i + 1);
            string secondChar = text.substring(i + 1, i + 2);
            string thirdChar = text.substring(i + 2, i + 3);
            string fourthChar = text.substring(i + 3, i + 4);
            
            integer firstBit = mBase64To6BitMap.get(firstChar);
            if (firstBit == null)
                throw new RuntimeException('Invalid base 64 character: ' + firstChar);
            
            integer secondBit = mBase64To6BitMap.get(secondChar);
            if (secondBit == null)
                throw new RuntimeException('Invalid base 64 character: ' + secondBit);
                
            integer thirdBit = null;
            if (thirdChar != '=') {
                thirdBit = mBase64To6BitMap.get(thirdChar);
                if (thirdBit == null)
                    throw new RuntimeException('Invalid base 64 character: ' + thirdChar);
            }
            
            integer fourthBit = null;
            if (fourthChar != '=') {
                fourthBit = mBase64To6BitMap.get(fourthChar);
                if (fourthBit == null)
                    throw new RuntimeException('Invalid base 64 character: ' + fourthChar);
            }           
            
            result.add((firstBit << 2) | (secondBit >> 4));
            if (thirdBit != null)                
                result.add(((secondBit & 15) << 4) | (thirdBit >> 2));
            if (thirdBit != null && fourthBit != null)
                result.add(((thirdBit & 3) << 6) | fourthBit);
        }
          
        return result;
    }
    
    /*
     * Convert the given bytes into a base 64 encoded string.
     *
     * @param bytes The bytes to convert into a base 64 encoded string.
     * @return The base 64 encoded string that represents the bytes passed in.
     */
    public static string encodeBase64String(integer[] bytes) {
    
        if (bytes == null)
            throw new RuntimeException('bytes is null');            
            
        string[] result = new string[]{};
        integer bitsLength = bytes.size();
        
        for (integer i = 0; i < bitsLength; i += 3)
        {
            integer firstBit = bytes[i];
            integer secondBit = (i + 1 < bitsLength) ? bytes[i + 1] : null;
            integer thirdBit = (i + 2 < bitsLength) ? bytes[i + 2] : null;
            
            if (firstBit == null)
                throw new RuntimeException('bytes contains a null bit.');
                
            result.add(mBase64Table[(firstBit >> 2) & 63]);
            
            if (secondBit == null) {
                if (i + 1 < bitsLength)
                    throw new RuntimeException('bytes contains a null bit.');
            
                result.add(mBase64Table[(firstBit & 3) << 4]);
                result.add('==');
                break;
            }
            else if (thirdBit == null) {
                if (i + 2 < bitsLength)
                    throw new RuntimeException('bytes contains a null bit.');
                    
                result.add(mBase64Table[((firstBit & 3) << 4) | ((secondBit >> 4) & 15)]);
                result.add(mBase64Table[(secondBit & 15) << 2]);
                result.add('=');
                break;
            }   
            else {
                result.add(mBase64Table[((firstBit & 3) << 4) | ((secondBit >> 4) & 15)]);
                result.add(mBase64Table[((secondBit & 15) << 2) | ((thirdBit >> 6) & 3)]);
                result.add(mBase64Table[thirdBit & 63]);
            }         
        }
        
        return String.join(result, '');
    }
    
    /*
     * Convert a string that is a hex representation of a number into an integer value.
     *
     * @param hex The base 16 value to turn into a base 10 value.
     * @return The base 10 value of the given base 16 value.
     */
    public static integer encodeIntegerFromHex(string hex) {
        if (hex == null || hex.length() == 0)
            throw new RuntimeException('hex is null or empty.');
            
        string reversed = hex.reverse();
        
        integer result = 0;
        for (integer i = 0; i < hex.length(); i++) {
            string s = reversed.subString(i, i + 1);
            integer num = mHexMap.get(s);
            if (num == null)
                throw new RuntimeException('Invalid hex character: ' + s);
            result += (integer)(Math.pow(16, i) * num);
        }
            
        return result;
    }   
    
    /*
     * Convert a string into a UTF-16 encoded byte array.
     *
     * @param text The text to encode as a UTF-16 byte array.
     * @return The UTF-16 encoded byte array.
     */
    public static integer[] encodeUTF16String(string text) {
        integer[] result = new integer[]{};
        
        for (integer i = 0; i < text.length(); i++) {
            string hex = EncodingUtil.convertToHex(Blob.valueOf(text.subString(i, i + 1)));
            result.add(EncodeIntegerFromHex(hex));
            result.add(0);
        }
        
        return result;
    }
    
    /*
     * Convert a string into a UTF-8 encoded byte array.
     *
     * @param text The text to encode as a UTF-8 byte array.
     * @return The UTF-8 encoded byte array.
     */
    public static integer[] encodeUTF8String(string text) {
        integer[] result = new integer[]{};
        
        for (integer i = 0; i < text.length(); i++) {
            string hex = EncodingUtil.convertToHex(Blob.valueOf(text.subString(i, i + 1)));
            result.add(EncodeIntegerFromHex(hex));
        }
        
        return result;
    }
    
    /*
     * Get complement of the given integer.
     *
     * @param value The integer to get the complement for.
     * @return The complement of the given integer value.
     */
    public static integer getIntegerComplement(integer value) {
        return (value * -1) - 1;
    }
    
    /*
     * Get the unsigned 32-bit integer value from the given bytes starting at the offset.
     *
     * @param bytes The bytes to read the integer data from.
     * @param offset The offset to start reading the integer data from.
     * @return The integer read in from the given bytes.
     */
    public static integer toUInt32(integer[] bytes, integer offset) {
        integer result  = bytes[offset];
        result         |= bytes[offset + 1] << 8;
        result         |= bytes[offset + 2] << 16;
        result         |= bytes[offset + 3] << 24;   
        
        return result;
    }
    
    /*
     * Get the unsigned 16-bit integer value from the given bytes starting at the offset.
     *
     * @param offset The offset to start reading the integer data from.
     * @return The integer read in from the given bytes.
     */    
    public static integer toUInt16(integer[] bytes, integer offset) {
        integer result  = bytes[offset];
        result         |= bytes[offset + 1] << 8;
        
        return result;
    }
    
    /*
     * Get the bytes for the given blob value.
     *
     * @param value The blob to convert into a byte array.
     * @return The byte array converted from the given blob.
     */
    public static integer[] getBytes(blob value) {
        string hex = EncodingUtil.convertToHex(value);
        integer[] result = new integer[0];
        for (integer i = 0; i < hex.length(); i += 2)
            result.add(EncodeIntegerFromHex(hex.subString(i, i + 2)));        
            
        return result;
    }
    
    /*
     * Get the bytes that make up the given long value.
     *
     * @param value The value to convert into a byte array.
     * @return The byte array converted from the given value.
     */
    public static integer[] getBytesForUInt64(long value) {
        integer[] result = new integer[8];
        result[7] = (integer)(value >>> 56);
        result[6] = (integer)(value >>> 48) & 255;
        result[5] = (integer)(value >>> 40) & 255;
        result[4] = (integer)(value >>> 32) & 255;
        result[3] = (integer)(value >>> 24) & 255;
        result[2] = (integer)(value >>> 16) & 255;
        result[1] = (integer)(value >>> 8)  & 255;
        result[0] = (integer)(value)        & 255;
        
        return result;
    }
    
    /*
     * Get the bytes that make up the given integer value.
     *
     * @param value The value to convert into a byte array.
     * @return The byte array converted from the given value.
     */
    public static integer[] getBytesForUInt32(integer value) {
        integer[] result = new integer[4];
        result[3] = (integer)(value >>> 24) & 255;
        result[2] = (integer)(value >>> 16) & 255;
        result[1] = (integer)(value >>> 8)  & 255;
        result[0] = (integer)(value)        & 255;
        
        return result;
    }
    
    /*
     * Get the bytes that make up the given integer value.
     *
     * @param value The value to convert into a byte array.
     * @return The byte array converted from the given value.
     */  
    public static integer[] getBytesForUInt16(integer value) {
        integer[] result = new integer[2];
        result[1] = (integer)(value >>> 8)  & 255;
        result[0] = (integer)(value)        & 255;
        
        return result;
    }
    
    /*
     * Convert the given bytes into a blob.
     *
     * @param bytes The bytes to convert into a blob.
     * @return The blob converted from the given bytes.
     */
    public static blob getBlob(integer[] bytes) {
        string base64 = encodeBase64String(bytes);
        return EncodingUtil.base64Decode(base64);       
    }
}