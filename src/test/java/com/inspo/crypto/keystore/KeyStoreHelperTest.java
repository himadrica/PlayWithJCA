package com.inspo.crypto.keystore;

import static org.junit.Assert.*;

import java.security.KeyStore;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import com.inspo.crypto.symmetric.SymmetricEncryptionHelper;

public class KeyStoreHelperTest {

	@Test
    public void createPrivateKeyJavaKeyStore() throws Exception{
        SecretKey secretKey = SymmetricEncryptionHelper.createAESKey();
        String secretKeyHex = DatatypeConverter.printHexBinary(secretKey.getEncoded());
        KeyStore keyStore = KeyStoreHelper.createPrivateKeyJavaKeyStore("password", "foo", secretKey, "keyPassword");
        assertNotNull(keyStore);

        keyStore.load(null, "password".toCharArray());
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection("keyPassword".toCharArray());
        KeyStore.SecretKeyEntry resultEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("foo", entryPassword);
        SecretKey result = resultEntry.getSecretKey();
        String resultKeyHex = DatatypeConverter.printHexBinary(result.getEncoded());
        assertEquals(secretKeyHex, resultKeyHex);
    }
}
