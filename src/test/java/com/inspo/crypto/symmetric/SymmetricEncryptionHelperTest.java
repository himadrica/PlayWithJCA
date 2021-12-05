package com.inspo.crypto.symmetric;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import org.junit.Test;
import javax.xml.bind.DatatypeConverter;

public class SymmetricEncryptionHelperTest {

	@Test
	public void testCreateAESKey() throws NoSuchAlgorithmException {
		SecretKey key = SymmetricEncryptionHelper.createAESKey();
		assertNotNull(key);
		System.out.println(DatatypeConverter.printHexBinary(key.getEncoded()));
	}
	
	@Test
    public void testAESCyrptoRoutine() throws Exception{
        SecretKey key = SymmetricEncryptionHelper.createAESKey();
        byte[] initializationVector = SymmetricEncryptionHelper.createInitializationVector();
        String plainText = "This is the text we are going to hide in plain sight";
        byte[] cipherText = SymmetricEncryptionHelper.performAESEncyption(plainText, key, initializationVector);
        assertNotNull(cipherText);
        System.out.println(DatatypeConverter.printHexBinary(cipherText));
        String decryptedText = SymmetricEncryptionHelper.performAESDecryption(cipherText, key, initializationVector);
        assertEquals(plainText, decryptedText);
    }

}
