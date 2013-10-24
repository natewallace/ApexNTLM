/*
 * Unit tests for the BitConverter class. 
 *
 * @author Nate Wallace
 */
@isTest
private class BitConverterTest {

    /*
     * Test the DecodeBase64String method.
     */
    static testMethod void decodeBase64StringTest() {
    
        integer[] bits = BitConverter.decodeBase64String('TWFu');
        System.assertNotEquals(null, bits, 'result1 is null.');
        System.assertEquals(3, bits.size(), 'result1 isn\'t 3 bits.');
        System.assertEquals(77, bits[0], 'result1 bits[0] isn\'t 77');
        System.assertEquals(97, bits[1], 'result1 bits[0] isn\'t 97');
        System.assertEquals(110, bits[2], 'result1 bits[0] isn\'t 110');
        
        bits = BitConverter.decodeBase64String('TWE=');
        System.assertNotEquals(null, bits, 'result2 is null.');
        System.assertEquals(2, bits.size(), 'result2 isn\'t 3 bits.');
        System.assertEquals(77, bits[0], 'result2 bits[0] isn\'t 77');
        System.assertEquals(97, bits[1], 'result2 bits[0] isn\'t 97');       
        
        bits = BitConverter.decodeBase64String('TQ==');
        System.assertNotEquals(null, bits, 'result3 is null.');
        System.assertEquals(1, bits.size(), 'result3 isn\'t 3 bits.');
        System.assertEquals(77, bits[0], 'result3 bits[0] isn\'t 77');
        
        try {
            bits = BitConverter.decodeBase64String(null);
            System.assert(false, 'Exception not thrown for null text.');
        } catch (Exception err) {
        } 
        
        try {
            bits = BitConverter.decodeBase64String('TWF');
            System.assert(false, 'Exception not thrown for non multiple of 4 text.');
        } catch (Exception err) {
        }
         
        try {
            bits = BitConverter.decodeBase64String('*WFu');
            System.assert(false, 'Exception not thrown for invalid text in first char.');
        } catch (Exception err) {
        }  
        
        try {
            bits = BitConverter.decodeBase64String('T*Fu');
            System.assert(false, 'Exception not thrown for invalid text in second char.');
        } catch (Exception err) {
        }  
        
        try {
            bits = BitConverter.decodeBase64String('TW*u');
            System.assert(false, 'Exception not thrown for invalid text in third char.');
        } catch (Exception err) {
        }    
        
        try {
            bits = BitConverter.decodeBase64String('TWF*');
            System.assert(false, 'Exception not thrown for invalid text in fourth char.');
        } catch (Exception err) {
        }                                       
    }

    /*
     * Test the EncodeBase64String method.
     */
    static testMethod void encodeBase64StringTest() {
    
        string s = BitConverter.encodeBase64String(new integer[]{ 77, 97, 110 });
        System.assertEquals('TWFu', s, 'TWFu wasn\'t encoded correctly.');
        
        s = BitConverter.encodeBase64String(new integer[]{ 77, 97 });
        System.assertEquals('TWE=', s, 'TWE= wasn\'t encoded correctly.');
        
        s = BitConverter.encodeBase64String(new integer[]{ 77 });
        System.assertEquals('TQ==', s, 'TQ== wasn\'t encoded correctly.');
        
        try {        
            s = BitConverter.encodeBase64String(null);
            System.assert(false, 'Exception not thrown for null parameter.');
        } catch (Exception err) {
        }
                
        try {        
            s = BitConverter.encodeBase64String(new integer[]{ null, 97, 110 });
            System.assert(false, 'Exception not thrown for null character in first position.');
        } catch (Exception err) {
        }
        
        try {        
            s = BitConverter.encodeBase64String(new integer[]{ 77, null, 110 });
            System.assert(false, 'Exception not thrown for null character in second position.');
        } catch (Exception err) {
        }
        
        try {        
            s = BitConverter.encodeBase64String(new integer[]{ 77, 97, null });
            System.assert(false, 'Exception not thrown for null character in third position.');
        } catch (Exception err) {
        }
    }
    
    /*
     * Test the EncodeIntegerFromHex method.
     */
    static testMethod void encodeIntegerFromHexTest() {
        System.assertEquals(138, BitConverter.encodeIntegerFromHex('8A'), 'Failed to encode 8A');
        System.assertEquals(15, BitConverter.encodeIntegerFromHex('F'), 'Failed to encode F');
        System.assertEquals(939, BitConverter.encodeIntegerFromHex('3AB'), 'Failed to encode 3AB');
        
        try {        
            BitConverter.encodeIntegerFromHex(null);
            System.assert(false, 'Exception not thrown for null hex character.');
        } catch (Exception err) {
        }   
        
        try {        
            BitConverter.encodeIntegerFromHex('3X');
            System.assert(false, 'Exception not thrown for invalid hex character.');
        } catch (Exception err) {
        }          
    } 
    
    /*
     * Test the EncodeUTF16String method.
     */
    static testMethod void encodeUTF16StringTest() {
        integer[] result = BitConverter.encodeUTF16String('test');
        System.assertEquals(8, result.size(), 'Invalid number of bytes resulted.');
        System.assertEquals(116, result[0], 'result[0] != 116');
        System.assertEquals(0, result[1], 'result[1] != 0');
        System.assertEquals(101, result[2], 'result[2] != 101');
        System.assertEquals(0, result[3], 'result[3] != 0');
        System.assertEquals(115, result[4], 'result[4] != 115');
        System.assertEquals(0, result[5], 'result[5] != 0');
        System.assertEquals(116, result[6], 'result[6] != 116');
        System.assertEquals(0, result[7], 'result[7] != 0');
    }  
    
    /*
     * Test the EncodeUTF8String method.
     */
    static testMethod void encodeUTF8StringTest() {
        integer[] result = BitConverter.encodeUTF8String('test');
        System.assertEquals(4, result.size(), 'Invalid number of bytes resulted.');
        System.assertEquals(116, result[0], 'result[0] != 116');
        System.assertEquals(101, result[1], 'result[1] != 101');
        System.assertEquals(115, result[2], 'result[2] != 115');
        System.assertEquals(116, result[3], 'result[4] != 116');        
    }     
      
    /*
     * Test the getIntegerComplement method.
     */
    static testMethod void getIntegerComplementTest() {
        System.assertEquals(-14, BitConverter.getIntegerComplement(13), '~13 should equal -14');
    }
    
    /*
     * Test the toUInt32 method.
     */
    static testMethod void toUInt32Test() {
        integer result = BitConverter.toUInt32(new integer[] { 16, 4, 0, 0 }, 0);
        System.assertEquals(1040, result, 'result isn\'t 1040');
    }
        
    /*
     * Test the toUInt16 method.
     */
    static testMethod void toUInt16Test() {
        integer result = BitConverter.toUInt16(new integer[] { 16, 4 }, 0);
        System.assertEquals(1040, result, 'result isn\'t 1040');
    }        
         
    /*
     * Test the getBytes method.
     */
    static testMethod void getBytesTest() {
        integer[] blobTest = BitConverter.getBytes(Blob.valueOf('test'));
        System.assertEquals(4, blobTest.size(), 'blobTest isn\'t 4 bytes.');
        System.assertEquals(116, blobTest[0], 'blobTest[0] isn\'t 116');
        System.assertEquals(101, blobTest[1], 'blobTest[1] isn\'t 101');
        System.assertEquals(115, blobTest[2], 'blobTest[2] isn\'t 115');
        System.assertEquals(116, blobTest[3], 'blobTest[3] isn\'t 116');
    }
    
    /*
     * Test the getBytesForUInt64 method.
     */
    static testMethod void getBytesForUInt64Test() {
        long num = 32484390143099L;
        integer[] result = BitConverter.getBytesForUInt64(num);
        System.assertEquals(8, result.size(), 'result isn\'t 8 bytes.');
        System.assertEquals(123, result[0], 'result[0] != 123');
        System.assertEquals(4, result[1], 'result[1] != 4');
        System.assertEquals(137, result[2], 'result[2] != 137');
        System.assertEquals(92, result[3], 'result[3] != 92');
        System.assertEquals(139, result[4], 'result[4] != 139');
        System.assertEquals(29, result[5], 'result[5] != 29');
        System.assertEquals(0, result[6], 'result[6] != 0');
        System.assertEquals(0, result[7], 'result[7] != 0');
    }    
    
    /*
     * Test the getBytesForUInt32 method.
     */
    static testMethod void getBytesForUInt32Test() {
        integer num = 100900;
        integer[] result = BitConverter.getBytesForUInt32(num);
        System.assertEquals(4, result.size(), 'result isn\'t 4 bytes.');
        System.assertEquals(36, result[0], 'result[0] != 36');
        System.assertEquals(138, result[1], 'result[1] != 138');
        System.assertEquals(1, result[2], 'result[2] != 1');
        System.assertEquals(0, result[3], 'result[3] != 0');
    }   
    
    /*
     * Test the getBytesForUInt32 method.
     */
    static testMethod void getBytesForUInt16Test() {
        integer num = 500;
        integer[] result = BitConverter.getBytesForUInt16(num);
        System.assertEquals(2, result.size(), 'result isn\'t 2 bytes.');
        System.assertEquals(244, result[0], 'result[0] != 244');
        System.assertEquals(1, result[1], 'result[1] != 1');
    }    
    
    /*
     * Test the getBlob method.
     */
    static testMethod void getBlobTest() {
        integer[] bytes = new integer[] { 116, 101, 115, 116 };
        blob blobTest = BitConverter.getBlob(bytes);
        System.assertEquals(String.valueOf(Blob.valueOf('test')), String.valueOf(blobTest), 'blobs don\'t match.');
    }    
}