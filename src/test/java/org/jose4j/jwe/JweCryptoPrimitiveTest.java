package org.jose4j.jwe;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.jws.JwsTestSupport;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.keys.PbkdfKey;
import org.jose4j.lang.ByteUtil;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.PERMIT;

public class JweCryptoPrimitiveTest
{
    private static final Logger log = LoggerFactory.getLogger(JweCryptoPrimitiveTest.class);

    @Test
    public void exerciseTheApi() throws Exception
    {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        jwe.setPayload("SANTA! OH MY GOD! SANTA'S COMING! I KNOW HIM! I KNOW HIM!");
        String compactSerialization = jwe.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(compactSerialization);
        jwe.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        CryptoPrimitive cryptoPrimitive = jwe.prepareDecryptingPrimitive();
        Assert.assertNull(cryptoPrimitive.getKey());
        Assert.assertNull(cryptoPrimitive.getKeyAgreement());
        Assert.assertNull(cryptoPrimitive.getMac());
        Assert.assertNotNull(cryptoPrimitive.getCipher());
        log.debug("cryptoPrimitive.getCipher(): " + cryptoPrimitive.getCipher());
        Assert.assertNull(cryptoPrimitive.getSignature());
        Assert.assertTrue(jwe.getPayload().contains("SANTA!"));

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        jwe.setPayload("It’s not going in our yard, Russ. It’s going in our living room.");
        compactSerialization = jwe.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(compactSerialization);
        jwe.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        cryptoPrimitive = jwe.prepareDecryptingPrimitive();
        Assert.assertNull(cryptoPrimitive.getKey());
        Assert.assertNotNull(cryptoPrimitive.getKeyAgreement());
        log.debug("cryptoPrimitive.getKeyAgreement(): " + cryptoPrimitive.getKeyAgreement());
        Assert.assertNull(cryptoPrimitive.getMac());
        Assert.assertNull(cryptoPrimitive.getCipher());
        Assert.assertNull(cryptoPrimitive.getSignature());
        Assert.assertTrue(jwe.getPayload().contains("Russ"));

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        jwe.setPayload("Oh, the silent majesty of a winter’s morn, the clean, cool chill of the holiday air, an asshole in his bathrobe emptying a chemical toilet into my sewer.");
        compactSerialization = jwe.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(compactSerialization);
        jwe.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        cryptoPrimitive = jwe.prepareDecryptingPrimitive();
        Assert.assertNull(cryptoPrimitive.getKey());
        Assert.assertNotNull(cryptoPrimitive.getKeyAgreement());
        log.debug("cryptoPrimitive.getKeyAgreement(): " + cryptoPrimitive.getKeyAgreement());
        Assert.assertNull(cryptoPrimitive.getMac());
        Assert.assertNull(cryptoPrimitive.getCipher());
        Assert.assertNull(cryptoPrimitive.getSignature());
        Assert.assertTrue(jwe.getPayload().contains("bathrobe"));


        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        jwe.setPayload("Grace? She passed away 30 years ago!");
        compactSerialization = jwe.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(compactSerialization);
        jwe.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        cryptoPrimitive = jwe.prepareDecryptingPrimitive();
        Assert.assertNull(cryptoPrimitive.getKey());
        Assert.assertNotNull(cryptoPrimitive.getKeyAgreement());
        log.debug("cryptoPrimitive.getKeyAgreement(): " + cryptoPrimitive.getKeyAgreement());
        Assert.assertNull(cryptoPrimitive.getMac());
        Assert.assertNull(cryptoPrimitive.getCipher());
        Assert.assertNull(cryptoPrimitive.getSignature());
        Assert.assertTrue(jwe.getPayload().contains("Grace?"));



        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        AesKey aesKey = new AesKey(ByteUtil.randomBytes(32));
        jwe.setKey(aesKey);
        jwe.setPayload("When what to my wondering eyes should appear, but a miniature sleigh and... Eddie. With a man in his pajamas and a dog chain tied to his wrists and ankles.");
        compactSerialization = jwe.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(compactSerialization);
        jwe.setKey(aesKey);
        cryptoPrimitive = jwe.prepareDecryptingPrimitive();
        Assert.assertNotNull(cryptoPrimitive.getKey()); // DIRECT is kinda odd
        log.debug("cryptoPrimitive.getKey(): " + cryptoPrimitive.getKey());
        Assert.assertNull(cryptoPrimitive.getKeyAgreement());
        Assert.assertNull(cryptoPrimitive.getMac());
        Assert.assertNull(cryptoPrimitive.getCipher());
        Assert.assertNull(cryptoPrimitive.getSignature());
        Assert.assertTrue(jwe.getPayload().contains("pajamas"));


        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        aesKey = new AesKey(ByteUtil.randomBytes(16));
        jwe.setKey(aesKey);
        jwe.setPayload("I had a lot of help from Jack Daniels.");
        compactSerialization = jwe.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(compactSerialization);
        jwe.setKey(aesKey);
        cryptoPrimitive = jwe.prepareDecryptingPrimitive();
        Assert.assertNull(cryptoPrimitive.getKey()); // DIRECT is kinda odd
        Assert.assertNull(cryptoPrimitive.getKeyAgreement());
        Assert.assertNull(cryptoPrimitive.getMac());
        Assert.assertNotNull(cryptoPrimitive.getCipher());
        log.debug("cryptoPrimitive.getCipher(): " + cryptoPrimitive.getCipher());
        Assert.assertNull(cryptoPrimitive.getSignature());
        Assert.assertTrue(jwe.getPayload().contains("Jack"));


        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW);
        jwe.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW));
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        PbkdfKey pbkdfKey = new PbkdfKey("Don’t piss me off, Art.");
        jwe.setKey(pbkdfKey);
        jwe.setPayload("I’m sorry, this is our family’s first kidnapping.");
        compactSerialization = jwe.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW));
        jwe.setCompactSerialization(compactSerialization);
        jwe.setKey(pbkdfKey);
        cryptoPrimitive = jwe.prepareDecryptingPrimitive();
        Assert.assertNotNull(cryptoPrimitive.getKey()); // the PBES2 ones are kinda odd too - this is the derived key for lack of knowing something better
        log.debug("cryptoPrimitive.getKey(): " + cryptoPrimitive.getKey());
        Assert.assertNull(cryptoPrimitive.getKeyAgreement());
        Assert.assertNull(cryptoPrimitive.getMac());
        Assert.assertNull(cryptoPrimitive.getCipher());
        Assert.assertNull(cryptoPrimitive.getSignature());
        Assert.assertTrue(jwe.getPayload().contains("kidnapping"));
    }
}
