package com.inspo.crypto.hash;

import static org.junit.Assert.*;

import java.util.UUID;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

public class HashHelperTest {

	@Test
	public void testGenerateRandomSalt() {
		byte[] salt = HashHelper.generateRandomSalt();
		assertNotNull(salt);
		System.out.println(DatatypeConverter.printHexBinary(salt));
	}

	@Test
	public void testCreateSHA2Hash() throws Exception {
		byte[] salt = HashHelper.generateRandomSalt();
		String valueToHash = UUID.randomUUID().toString();
		byte[] hash = HashHelper.createSHA2Hash(valueToHash, salt);
		assertNotNull(hash);
		byte[] hash2 = HashHelper.createSHA2Hash(valueToHash, salt);
		assertEquals(DatatypeConverter.printHexBinary(hash), DatatypeConverter.printHexBinary(hash2));
	}

	@Test
	void testPasswordRoutine() {
		String secretPhrase = "correct horse battery staple";
		String passwordHash = HashHelper.hashPassword(secretPhrase);
		System.out.println(passwordHash);
		assertTrue(HashHelper.verifyPassord(secretPhrase, passwordHash));
	}
}
