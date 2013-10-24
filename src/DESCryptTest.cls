/*
 * Unit tests for the DESCryptTest class.
 */
@isTest
public class DESCryptTest {

    /*
     * Test the encrypt method.
     */
    static testMethod void encryptTest() {
        DESCrypt des = new DESCrypt();
        integer[] plainText = new integer[] { 72, 73, 32, 84, 72, 69, 82, 69 };
        integer[] keyBytes = new integer[] { 0, 1, 2, 3, 4, 5, 6, 7 };
        
        des.init(false, keyBytes);
        integer[] result = des.encrypt(plainText);
        
        System.assertEquals(183, result[0], 'result[0] isn\'t 183.');
        System.assertEquals(106, result[1], 'result[1] isn\'t 106.');
        System.assertEquals(35, result[2], 'result[2] isn\'t 35.');
        System.assertEquals(71, result[3], 'result[3] isn\'t 71.');
        System.assertEquals(105, result[4], 'result[4] isn\'t 105.');
        System.assertEquals(106, result[5], 'result[5] isn\'t 106.');
        System.assertEquals(126, result[6], 'result[6] isn\'t 126.');
        System.assertEquals(99, result[7], 'result[7] isn\'t 99.');
    }
    
}