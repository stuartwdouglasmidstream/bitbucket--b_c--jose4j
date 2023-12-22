/*
 * Copyright 2012-2017 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.jwk;

import org.jose4j.json.JsonUtil;
import org.jose4j.keys.EdDsaKeyUtil;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.keys.XDHKeyUtil;
import org.jose4j.lang.JoseException;
import static org.junit.Assert.*;
import org.junit.Test;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 */
public class JsonWebKeyTest
{
    @Test
    public void factoryWithXOctetKeyPairJsonWebKey() throws JoseException
    {
        // skip this test if XDH isn't available
        org.junit.Assume.assumeTrue(new XDHKeyUtil().isAvailable());

        String jwkJson = "{\"kty\":\"OKP\",\"d\":\"T4gjxXciGdlPcWC1Pgba0cptraIx8ZjORUyR-ttweZQ\"," +
                "\"crv\":\"X25519\",\"x\":\"qPRE1ElE6NArtJ0rhMkjaR8_PJZLf6v6Zk_4Vo72jho\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        assertTrue(jwk instanceof OctetKeyPairJsonWebKey);
        assertEquals(OctetKeyPairJsonWebKey.KEY_TYPE, jwk.getKeyType());
        assertTrue(XDHKeyUtil.isXECPublicKey(jwk.getKey()));
        assertTrue(XDHKeyUtil.isXECPrivateKey(((PublicJsonWebKey) jwk).getPrivateKey()));
    }

    @Test
    public void factoryWithEdOctetKeyPairJsonWebKey() throws JoseException
    {
        // skip this test if EdDSA isn't available
        org.junit.Assume.assumeTrue(new EdDsaKeyUtil().isAvailable());

        String jwkJson = "{\"kty\":\"OKP\"," +
                "\"d\":\"Y6KQHffZKlIXW1JdVvEBJCliWtuYk3pYQJoeSvfJEAw\"," +
                "\"crv\":\"Ed25519\"," +
                "\"x\":\"Jp1b9nhTp_Z2YmHC22k5oy32dIIWYOhiaD8PJQFcxgU\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        assertTrue(jwk instanceof OctetKeyPairJsonWebKey);
        assertEquals(OctetKeyPairJsonWebKey.KEY_TYPE, jwk.getKeyType());
        assertTrue(EdDsaKeyUtil.isEdECPublicKey(jwk.getKey()));
        assertTrue(EdDsaKeyUtil.isEdECPrivateKey(((PublicJsonWebKey) jwk).getPrivateKey()));
    }


    @Test
    public void testFactoryWithRsaPublicKey() throws JoseException
    {
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(ExampleRsaKeyFromJws.PUBLIC_KEY);
        assertIsRsa(jwk);
    }

    @Test(expected = JoseException.class)
    public void testFactoryFailWithRsaPrivateKey() throws JoseException
    {
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(ExampleRsaKeyFromJws.PRIVATE_KEY);
    }

    private void assertIsRsa(JsonWebKey jwk)
    {
        assertTrue(jwk instanceof RsaJsonWebKey);
        assertTrue(jwk.getKey() instanceof RSAPublicKey);
        assertEquals(RsaJsonWebKey.KEY_TYPE, jwk.getKeyType());
    }

    @Test
    public void testFactoryWithEcPublicKey() throws JoseException
    {
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(ExampleEcKeysFromJws.PUBLIC_256);
        assertIsEllipticCurve(jwk);
    }

    @Test(expected = JoseException.class)
    public void testFactoryFailWithEcPrivateKey() throws JoseException
    {
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(ExampleEcKeysFromJws.PRIVATE_256);
    }

    private void assertIsEllipticCurve(JsonWebKey jwk)
    {
        assertTrue(jwk.getKey() instanceof ECPublicKey);
        assertTrue(jwk instanceof EllipticCurveJsonWebKey);
        assertEquals(EllipticCurveJsonWebKey.KEY_TYPE, jwk.getKeyType());
    }

    @Test
    public void testEcSingleJwkToAndFromJson() throws JoseException
    {
        String jwkJson =
                "       {\"kty\":\"EC\",\n" +
                "        \"crv\":\"P-256\",\n" +
                "        \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\n" +
                "        \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\n" +
                "        \"use\":\"enc\",\n" +
                "        \"kid\":\"1\"}";

        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        assertIsEllipticCurve(jwk);

        String jsonOut = jwk.toJson();
        JsonWebKey jwk2 = JsonWebKey.Factory.newJwk(jsonOut);
        assertIsEllipticCurve(jwk2);

        checkEncoding(jsonOut, EllipticCurveJsonWebKey.X_MEMBER_NAME, EllipticCurveJsonWebKey.Y_MEMBER_NAME);
    }

    @Test
    public void testRsaSingleJwkToAndFromJson() throws JoseException
    {
        String jwkJson =
                  "       {\"kty\":\"RSA\",\n" +
                "        \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                "   4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                "   tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                "   QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                "   SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                "   w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
                "        \"e\":\"AQAB\",\n" +
                "        \"alg\":\"RS256\"}";

        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        assertIsRsa(jwk);

        String jsonOut = jwk.toJson();
        JsonWebKey jwk2 = JsonWebKey.Factory.newJwk(jsonOut);
        assertIsRsa(jwk2);

        checkEncoding(jwk.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY), RsaJsonWebKey.MODULUS_MEMBER_NAME);
    }

    static void checkEncoding(String jwkJson, String... members) throws JoseException
    {
        Map<String,Object> parsed = JsonUtil.parseJson(jwkJson);
        for (String name : members)
        {
            // not base64
            String value = (String)parsed.get(name);
            assertEquals(-1, value.indexOf('\r'));
            assertEquals(-1, value.indexOf('\n'));
            assertEquals(-1, value.indexOf('='));
            assertEquals(-1, value.indexOf('+'));
            assertEquals(-1, value.indexOf('/'));
        }
    }

    @Test
    public void testKeyOps() throws Exception
    {
        String json = "{\"kty\":\"oct\",\"k\":\"Hdd5Uqtga_B4UilmahWJR8juxF_zw1_xaWeUGAvbg9c\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(json);
        assertNull(jwk.getKeyOps());
        List<String> keyOps = Arrays.asList(KeyOperations.DECRYPT, KeyOperations.DERIVE_BITS, KeyOperations.DERIVE_KEY,
                KeyOperations.ENCRYPT, KeyOperations.SIGN, KeyOperations.VERIFY, KeyOperations.UNWRAP_KEY, KeyOperations.WRAP_KEY);
        jwk.setKeyOps(keyOps);
        json = jwk.toJson(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC);
        assertTrue(json.contains("\""+JsonWebKey.KEY_OPERATIONS+"\""));
        jwk = JsonWebKey.Factory.newJwk(json);
        List<String> keyOpsFromParsed = jwk.getKeyOps();
        assertTrue(Arrays.equals(keyOps.toArray(), keyOpsFromParsed.toArray()));

        json = "{\"kty\":\"oct\",\"key_ops\":[\"decrypt\",\"encrypt\"],\"k\":\"add14qyge_v4sscm2hWJR8juxF_____cpW8U3ahcp__\"}";
        jwk = JsonWebKey.Factory.newJwk(json);
        assertEquals(2, jwk.getKeyOps().size());
        assertTrue(jwk.getKeyOps().contains(KeyOperations.ENCRYPT));
        assertTrue(jwk.getKeyOps().contains(KeyOperations.DECRYPT));
    }


    @Test (expected = JoseException.class)
    public void howHandleWrongType1() throws Exception
    {
        JsonWebKey.Factory.newJwk("{\"kty\":1}");
    }

    @Test (expected = JoseException.class)
    public void howHandleWrongType2() throws Exception
    {
        String jwkJson =
                "       {\"kty\":\"RSA\",\n" +
                "        \"n\": 8929747471717373711113313454114,\n" +
                "        \"e\":\"AQAB\",\n" +
                "        \"alg\":\"RS256\"}";
        JsonWebKey.Factory.newJwk(jwkJson);
    }

    @Test (expected = JoseException.class)
    public void howHandleWrongType3() throws Exception
    {
        String jwkJson =
                "       {\"kty\":\"EC\",\n" +
                "        \"crv\":\"P-256\",\n" +
                "        \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\n" +
                "        \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\n" +
                "        \"use\":true,\n" +
                "        \"kid\":\"1\"}";
        JsonWebKey.Factory.newJwk(jwkJson);
    }

    @Test (expected = JoseException.class)
    public void howHandleWrongType4() throws Exception
    {
        String jwkJson =
                "       {\"kty\":\"EC\",\n" +
                "        \"crv\":\"P-256\",\n" +
                "        \"x\":[\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"],\n" +
                "        \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\n" +
                "        \"kid\":\"1s\"}";
        JsonWebKey.Factory.newJwk(jwkJson);
    }
}
