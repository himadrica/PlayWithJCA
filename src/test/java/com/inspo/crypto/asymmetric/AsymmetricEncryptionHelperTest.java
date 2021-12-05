package com.inspo.crypto.asymmetric;

import static org.junit.Assert.*;

import java.security.KeyPair;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

public class AsymmetricEncryptionHelperTest {

	@Test
	public void testGenerateRSAKeyPair() throws Exception {
		 KeyPair keyPair = AsymmetricEncryptionHelper.generateRSAKeyPair();
	        assertNotNull(keyPair);
	        System.out.println("Private Key: " + DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
	        System.out.println("Public Key:  " + DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));
	}

	@Test
    public void testRSACryptoRoutine() throws Exception{
        KeyPair keyPair = AsymmetricEncryptionHelper.generateRSAKeyPair();
        String plainText = "This is the text we are going to hide in plain sight";
        byte[] cipherText = AsymmetricEncryptionHelper.performRSAEncryption(plainText, keyPair.getPrivate());
        assertNotNull(cipherText);
        System.out.println(DatatypeConverter.printHexBinary(cipherText));
        String decryptedText = AsymmetricEncryptionHelper.performRSADecryption(cipherText, keyPair.getPublic());
        assertEquals(plainText, decryptedText);
	}
}
