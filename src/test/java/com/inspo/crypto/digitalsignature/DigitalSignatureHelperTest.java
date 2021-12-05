package com.inspo.crypto.digitalsignature;

import static org.junit.Assert.*;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import com.inspo.crypto.asymmetric.AsymmetricEncryptionHelper;

public class DigitalSignatureHelperTest {

	@Test
	public void digitalSignatureRoutine() throws Exception {
		URL uri = this.getClass().getClassLoader().getResource("demo.txt");
		Path path = Paths.get(uri.toURI());
		byte[] input = Files.readAllBytes(path);

		KeyPair keyPair = AsymmetricEncryptionHelper.generateRSAKeyPair();
		byte[] signature = DigitalSignatureHelper.createDigitalSignature(input, keyPair.getPrivate());
		System.out.println(DatatypeConverter.printHexBinary(signature));
		assertTrue(DigitalSignatureHelper.verifyDigitalSignature(input, signature, keyPair.getPublic()));
	}

}
