package com.inspo.crypto.symmetric;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

// Make sure you enablue unlimitted 
public class SymmetricEncryptionHelper {
	private static final String AES = "AES";
	/*
	 * The AES algorithm has six modes of operation:
		ECB (Electronic Code Book)
		CBC (Cipher Block Chaining)
		CFB (Cipher FeedBack)
		OFB (Output FeedBack)
		CTR (Counter)
		GCM (Galois/Counter Mode)
		https://www.baeldung.com/java-aes-encryption-decryption
	 */
	private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	
	public static SecretKey createAESKey() throws NoSuchAlgorithmException {
		SecureRandom secureRandom = new SecureRandom();
		KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
		keyGenerator.init(256,secureRandom);
		return keyGenerator.generateKey();
	}
	
	public static byte[] createInitializationVector(){
        byte[] initializationVector = new byte[16]; //The block size of AES is 16 bytes
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

    public static byte[] performAESEncyption(String plainText, SecretKey secretKey, byte[] initializationVector) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String performAESDecryption(byte[] cipherText, SecretKey secretKey, byte[] initializationVector) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }
}
