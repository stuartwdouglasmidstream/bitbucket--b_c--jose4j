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

package org.jose4j.jwt.consumer;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.JceProviderTestSupport;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.OctJwkGenerator;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwk.SimpleJwkFilter;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.keys.FakeHsmNonExtractableSecretKeySpec;
import org.jose4j.keys.HmacKey;
import org.jose4j.keys.PbkdfKey;
import org.jose4j.keys.resolvers.DecryptionKeyResolver;
import org.jose4j.keys.resolvers.JwksDecryptionKeyResolver;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.Assert;
import org.junit.Test;

import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers.AES_128_GCM;
import static org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers.AES_192_GCM;
import static org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers.AES_256_GCM;
import static org.jose4j.jwe.KeyManagementAlgorithmIdentifiers.*;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.hamcrest.MatcherAssert.assertThat;



/**
 *
 */
public class JwtConsumerTest
{
    @Test
    public void jwt61ExampleUnsecuredJwt() throws InvalidJwtException, MalformedClaimException
    {
        // an Example Unsecured JWT from https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-6.1
        String jwt =
                "eyJhbGciOiJub25lIn0" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                ".";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);
        assertThat("joe", equalTo(jwtContext.getJwtClaims().getIssuer()));
        assertThat(NumericDate.fromSeconds(1300819380), equalTo(jwtContext.getJwtClaims().getExpirationTime()));
        Assert.assertTrue(jwtContext.getJwtClaims().getClaimValue("http://example.com/is_root", Boolean.class));

        // works w/ 'NO_CONSTRAINTS' and setDisableRequireSignature() and null key
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKey(null)
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .setDisableRequireSignature()
                .build();
        JwtClaims jcs = consumer.processToClaims(jwt);
        assertThat("joe", equalTo(jcs.getIssuer()));
        assertThat(NumericDate.fromSeconds(1300819380), equalTo(jcs.getExpirationTime()));
        Assert.assertTrue(jcs.getClaimValue("http://example.com/is_root", Boolean.class));

        consumer.processContext(jwtContext);

        // just ensure that getting claims that aren't there returns null (or empty for string list) and doesn't throw an exception
        Assert.assertNull(jcs.getStringClaimValue("no-such-claim"));
        Assert.assertNull(jcs.getClaimValue("no way jose", Boolean.class));
        Assert.assertFalse(jcs.hasClaim("nope"));
        Assert.assertTrue(jcs.getStringListClaimValue("nope").isEmpty());

        Assert.assertTrue(jcs.hasClaim("http://example.com/is_root"));
        Object objectClaimValue = jcs.getClaimValue("http://example.com/is_root");
        Assert.assertNotNull(objectClaimValue);

        Assert.assertFalse(jcs.hasClaim("nope"));
        objectClaimValue = jcs.getClaimValue("nope");
        Assert.assertNull(objectClaimValue);


        // fails w/ default constraints
        consumer = new JwtConsumerBuilder()
                .setVerificationKey(null)
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .build();
         SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

        // fails w/ explicit constraints
        consumer = new JwtConsumerBuilder()
                .setVerificationKey(null)
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLOCK, AlgorithmIdentifiers.NONE, AlgorithmIdentifiers.RSA_PSS_USING_SHA256))
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);


        // fail w/ 'NO_CONSTRAINTS' but a key provided
        consumer = new JwtConsumerBuilder()
                .setVerificationKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getKey())
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

        // fail w/ 'NO_CONSTRAINTS' and no key but sig required (by default)
        consumer = new JwtConsumerBuilder()
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);
    }

    @Test
    public void jwtA1ExampleEncryptedJWT() throws InvalidJwtException, MalformedClaimException
    {
        // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#appendix-A.1
        String jwt = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
                "QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtM" +
                "oNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLG" +
                "TkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26ima" +
                "sOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52" +
                "YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a" +
                "1rZgN5TiysnmzTROF869lQ." +
                "AxY8DCtDaGlsbGljb3RoZQ." +
                "MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaM" +
                "HDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8." +
                "fiK51VwhsxJ-siBMR-YFiA";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey())
                .setJweAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, RSA1_5))
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);

        JwtConsumer c = new JwtConsumerBuilder()
                .setExpectedIssuer("joe")
                .setEvaluationTime(NumericDate.fromSeconds(1300819300))
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey())
                .setJweAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, RSA1_5))
                .setDisableRequireSignature()
                .build();

        c.processContext(jwtContext);

        JwtContext context = c.process(jwt);
        JwtClaims jcs = context.getJwtClaims();
        Assert.assertTrue(jcs.getClaimValue("http://example.com/is_root", Boolean.class));
        String expectedPayload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
        assertThat(jcs.getRawJson(), equalTo(expectedPayload));
        assertThat(1, equalTo(context.getJoseObjects().size()));
        assertThat(context.getJwt(), equalTo(jwt));
    }

    @Test
    public void jwtA2ExampleNestedJWT() throws InvalidJwtException, MalformedClaimException
    {
       // an Example Nested JWT from https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#appendix-A.2
       String jwt =
               "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU" +
               "In0." +
               "g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M" +
               "qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE" +
               "b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh" +
               "DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D" +
               "YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq" +
               "JGTO_z3Wfo5zsqwkxruxwA." +
               "UmVkbW9uZCBXQSA5ODA1Mg." +
               "VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB" +
               "BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT" +
               "-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10" +
               "l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY" +
               "Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr" +
               "ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2" +
               "8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE" +
               "l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U" +
               "zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd" +
               "_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ." +
               "AVO9iT5AV4CzvDJCdhSFlQ";

        PrivateKey decryptionKey = ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey();

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .setDecryptionKey(decryptionKey)
                .setJweAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, RSA1_5))
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);

        RSAPublicKey verificationKey = ExampleRsaKeyFromJws.PUBLIC_KEY;
        JwtConsumerBuilder builder = new JwtConsumerBuilder()
                .setDecryptionKey(decryptionKey)
                .setJweAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, RSA1_5))
                .setEnableRequireEncryption()
                .setVerificationKey(verificationKey)
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819380))
                .setAllowedClockSkewInSeconds(30)
                .setExpectedIssuer("joe");
        JwtConsumer jwtConsumer = builder.build();

        jwtConsumer.processContext(jwtContext);

        JwtContext jwtInfo = jwtConsumer.process(jwt);

        for (JwtContext ctx : new JwtContext[] {jwtContext, jwtInfo})
        {
            assertThat(2, equalTo(ctx.getJoseObjects().size()));
            Assert.assertTrue(ctx.getJoseObjects().get(0) instanceof JsonWebSignature);
            Assert.assertTrue(ctx.getJoseObjects().get(1) instanceof JsonWebEncryption);
            assertThat(ctx.getJwt(), equalTo(jwt));

            JwtClaims jcs = ctx.getJwtClaims();

            assertThat("joe", equalTo(jcs.getIssuer()));
            assertThat(NumericDate.fromSeconds(1300819380), equalTo(jcs.getExpirationTime()));
            Assert.assertTrue(jcs.getClaimValue("http://example.com/is_root", Boolean.class));
        }


        // then some negative tests w/ null or wrong keys
        builder = new JwtConsumerBuilder()
                .setDecryptionKey(null)
                .setEnableRequireEncryption()
                .setVerificationKey(verificationKey)
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819380))
                .setAllowedClockSkewInSeconds(30)
                .setExpectedIssuer("joe");
        jwtConsumer = builder.build();
        // no decryption key so we expect this jwtConsumer to fail on the raw JWT
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, null, jwtConsumer);
        // but it will work on the jwtContext because the JWE was already decrypted
        jwtConsumer.processContext(jwtContext);

        builder = new JwtConsumerBuilder()
                .setDecryptionKey(decryptionKey)
                .setEnableRequireEncryption()
                .setVerificationKey(null)
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819380))
                .setAllowedClockSkewInSeconds(30)
                .setExpectedIssuer("joe");
        jwtConsumer = builder.build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext,  jwtConsumer);

        builder = new JwtConsumerBuilder()
                .setDecryptionKey(decryptionKey)
                .setEnableRequireEncryption()
                .setVerificationKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey())
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819380))
                .setAllowedClockSkewInSeconds(30)
                .setExpectedIssuer("joe");
        jwtConsumer = builder.build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext,  jwtConsumer);
    }

    @Test
    public void jwtSec31ExampleJWT() throws Exception
    {
        // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-3.1
        String jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);
        Assert.assertTrue(jwtContext.getJwtClaims().getClaimValue("http://example.com/is_root", Boolean.class));
        assertThat(1, equalTo(jwtContext.getJoseObjects().size()));

        String jwk = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";

        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(jwk);
        JwksVerificationKeyResolver resolver = new JwksVerificationKeyResolver(Collections.singletonList(jsonWebKey));
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(resolver)
                .setEvaluationTime(NumericDate.fromSeconds(1300819372))
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .build();
        JwtContext context = consumer.process(jwt);
        Assert.assertTrue(context.getJwtClaims().getClaimValue("http://example.com/is_root", Boolean.class));
        assertThat(1, equalTo(context.getJoseObjects().size()));

        consumer.processContext(jwtContext);

        // require encryption and it will fail
        consumer = new JwtConsumerBuilder()
                .setEnableRequireEncryption()
                .setVerificationKey(jsonWebKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1300819372))
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);
    }

    @Test
    public void skipSignatureVerification() throws Exception
    {
        String jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setEvaluationTime(NumericDate.fromSeconds(1300819372))
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .build();
        JwtContext context = consumer.process(jwt);
        Assert.assertTrue(context.getJwtClaims().getClaimValue("http://example.com/is_root", Boolean.class));
        assertThat(1, equalTo(context.getJoseObjects().size()));
    }

    @Test (expected = InvalidJwtSignatureException.class)
    public void jwtBadSig() throws Exception
    {
        String jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLAogImV4cCI6MTkwMDgxOTM4MCwKICJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String jwk = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKey(JsonWebKey.Factory.newJwk(jwk).getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1900000380))
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .build();
        consumer.process(jwt);
    }

    @Test
    public void algConstraints() throws Exception
    {
        String jwt =
                "eyJ6aXAiOiJERUYiLCJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0" +
                ".DDyrirrztC88OaDtTkkNgNIyZqQd4gjWrab9KkiBnyOULjWZWt-IAg" +
                ".Obun_t7l3FYqNUqyW46syg" +
                ".ChlzoLTN1ovJP9PLHlirc-_yvP4ya_5gdhDSKiZnifS9MjCbeMYebkOCxSHexs09PBbPv30JwtIyM7caqkSNggA8HT_ub1moMpx0uOFhTE9dpdY4Wb4Ym6mqtIQhdwLymDVCI6vRn-NH88vdLluGSYYLhelgcL05qeWJQKzV3mxopgM-Q7N7LycXrodqTdvM" +
                ".ay9pwehz96tJgRKvSwASDg";

        JsonWebKey wrapKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"sUMs42PKNsKn9jeGJ2szKA\"}");

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);
        assertThat("eh", equalTo(jwtContext.getJwtClaims().getStringClaimValue("message")));

        JsonWebKey macKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"j-QRollN4PYjebWYcTl32YOGWfdpXi_YYHu03Ifp8K4\"}");

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        JwtClaims jwtClaims = consumer.processToClaims(jwt);
        assertThat("eh", equalTo(jwtClaims.getStringClaimValue("message")));
        consumer.processContext(jwtContext);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.HMAC_SHA256))
                .setJweAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, KeyManagementAlgorithmIdentifiers.A128KW))
                .setJweContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256))
                .build();
        jwtClaims = consumer.processToClaims(jwt);
        assertThat("eh", equalTo(jwtClaims.getStringClaimValue("message")));
        consumer.processContext(jwtContext);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.HMAC_SHA256)
                .setJweAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, KeyManagementAlgorithmIdentifiers.A128KW)
                .setJweContentEncryptionAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256)
                .build();
        jwtClaims = consumer.processToClaims(jwt);
        assertThat("eh", equalTo(jwtClaims.getStringClaimValue("message")));
        consumer.processContext(jwtContext);


        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLOCK, AlgorithmIdentifiers.HMAC_SHA256))
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLOCK, AlgorithmIdentifiers.HMAC_SHA256)
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJweAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLOCK, KeyManagementAlgorithmIdentifiers.A128KW))
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJweAlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLOCK, KeyManagementAlgorithmIdentifiers.A128KW)
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJweContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLOCK, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256))
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJweContentEncryptionAlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLOCK, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256)
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

        // wrong mac key
        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"___RollN4PYjebWYcTl32YOGWfdpXi_YYHu03Ifp8K4\"}").getKey())
                .setSkipAllValidators()
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

    }

    @Test
    public void customValidatorTest() throws Exception
    {
        // {"iss":"same","aud":"same","exp":1420046060}
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzYW1lIiwiYXVkIjoic2FtZSIsImV4cCI6MTQyMDA0NjA2MH0.O1w_nkfQMZvEEvJ0Pach0gPmJUMW8o4aFlA1f2c8m-I";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);

        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"IWlxz1h43wKzyigIXNn-dTRBu89M9L8wmJK4zZmUXrQ\"}");
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046040))
                .setExpectedAudience("same", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .build();

        JwtContext process = consumer.process(jwt);
        assertThat(1, equalTo(process.getJoseObjects().size()));
        consumer.processContext(jwtContext);

        consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046040))
                .setExpectedAudience("same", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .registerValidator(new Validator()
                {
                    @Override
                    public String validate(JwtContext jwtContext) throws MalformedClaimException
                    {
                        JwtClaims jcs = jwtContext.getJwtClaims();
                        String audience = jcs.getAudience().iterator().next();
                        String issuer = jcs.getIssuer();

                        if (issuer.equals(audience))
                        {
                            return "You can go blind issuing tokens to yourself...";
                        }

                        return null;
                    }
                })
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);
    }

    @Test
    public void customErrorCodeValidatorTest() throws Exception
    {
        // {"iss":"same","aud":"same","exp":1420046060}
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzYW1lIiwiYXVkIjoic2FtZSIsImV4cCI6MTQyMDA0NjA2MH0.O1w_nkfQMZvEEvJ0Pach0gPmJUMW8o4aFlA1f2c8m-I";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);

        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"IWlxz1h43wKzyigIXNn-dTRBu89M9L8wmJK4zZmUXrQ\"}");
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046040))
                .setExpectedAudience("same", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .build();

        final int errorCode = -76717;

        JwtContext process = consumer.process(jwt);
        assertThat(1, equalTo(process.getJoseObjects().size()));
        consumer.processContext(jwtContext);

        consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046040))
                .setExpectedAudience("same", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .registerValidator(new ErrorCodeValidator()
                {
                    @Override
                    public Error validate(JwtContext jwtContext) throws MalformedClaimException
                    {
                        JwtClaims jcs = jwtContext.getJwtClaims();
                        String audience = jcs.getAudience().iterator().next();
                        String issuer = jcs.getIssuer();

                        if (issuer.equals(audience))
                        {

                            return new Error(errorCode, "You can go blind issuing tokens to yourself...");
                        }

                        return null;
                    }
                })
                .build();

        InvalidJwtException invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

        assertTrue(invalidJwtException.hasErrorCode(errorCode));
        assertFalse(invalidJwtException.hasExpired());
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.MALFORMED_CLAIM));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.EXPIRATION_TOO_FAR_IN_FUTURE));
    }

    @Test
    public void errorExpiredErrorCodeValidation() throws Exception
    {
        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setExpirationTimeMinutesInTheFuture(-1);
        jwtClaims.setIssuer("ISS");
        jwtClaims.setAudience("AUD");
        jwtClaims.setSubject("SUB");

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(jwtClaims.toJson());
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        String jwt = jws.getCompactSerialization();

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setExpectedAudience("AUD")
                .setExpectedIssuer("ISS")
                .setRequireExpirationTime()
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .build();

        InvalidJwtException invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);
        assertTrue(invalidJwtException.hasExpired());
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.AUDIENCE_MISSING));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.AUDIENCE_INVALID));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.ISSUER_INVALID));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.ISSUER_MISSING));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.NOT_YET_VALID));
    }

    @Test
    public void varietyOfErrorCodeValidation() throws Exception
    {
        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setExpirationTimeMinutesInTheFuture(10);
        jwtClaims.setIssuer("ISS");
        jwtClaims.setAudience("AUD");
        jwtClaims.setSubject("SUB");

        JsonWebSignature jws = new JsonWebSignature();
        String claimsJson = jwtClaims.toJson();
        jws.setPayload(claimsJson);
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        String jwt = jws.getCompactSerialization();

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setExpectedAudience("nope")
                .setExpectedIssuer("ISS")
                .setRequireExpirationTime()
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .build();

        InvalidJwtException invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.AUDIENCE_INVALID));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.AUDIENCE_MISSING));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.EXPIRED));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.ISSUER_INVALID));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.ISSUER_MISSING));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.NOT_YET_VALID));

        consumer = new JwtConsumerBuilder()
                .setExpectedAudience("AUD")
                .setExpectedIssuer("no way")
                .setRequireExpirationTime()
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .build();

        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.ISSUER_INVALID));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.AUDIENCE_MISSING));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.EXPIRED));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.AUDIENCE_INVALID));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.ISSUER_MISSING));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.NOT_YET_VALID));

        consumer = new JwtConsumerBuilder()
                .setMaxFutureValidityInMinutes(5)
                .setExpectedAudience("nope")
                .setExpectedIssuer("no way")
                .setRequireExpirationTime()
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .build();

        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.ISSUER_INVALID));
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.AUDIENCE_INVALID));
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.EXPIRATION_TOO_FAR_IN_FUTURE));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.AUDIENCE_MISSING));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.EXPIRED));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.ISSUER_MISSING));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.NOT_YET_VALID));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.SIGNATURE_INVALID));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.SIGNATURE_MISSING));

        consumer = new JwtConsumerBuilder()
                .setMaxFutureValidityInMinutes(55)
                .setExpectedAudience("AUD")
                .setExpectedIssuer("ISS")
                .setRequireExpirationTime()
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .build();

        JwtContext process = consumer.process(jwt);
        assertThat("SUB", equalTo(process.getJwtClaims().getSubject()));

        String[] parts = CompactSerializer.deserialize(jwt);
        parts[2] = "NGns23fwIfHwxj0tDsFcFuzrlZYopHMWm5gaUzZyNdAwfLU3n_idriThNBjcA2Y68-3cw6IJs9sGmPlNVmXOtEG5n5DrjjmMLCpoeBvLmKW_sCPM35Dx62ZCoi4_" +
                "QlfZvOVoSfzR9i7_9QwAmpRiPYBFLC3SVH2exH3Cr3FKIKqADeOf3yo86w22JaftSRcpA0I1wVOGvCvrw2EfO1nFuhl5g7Wp1Jl1aRnmYPo9v656Dq_" +
                "zfmdNY8W9yGeuNXnpPTx4gXeQ2GbXS95vBzansM769TPtNaEC_kaQxzYMdPmc1MkAwqFcw6RQ6Qfv4JUwKs19XGwAuWLN8vT6djTODw";
        String badSigJwt = CompactSerializer.serialize(parts);
        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(badSigJwt, consumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.SIGNATURE_INVALID));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.AUDIENCE_INVALID));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.EXPIRATION_TOO_FAR_IN_FUTURE));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.AUDIENCE_MISSING));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.EXPIRED));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.ISSUER_MISSING));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.NOT_YET_VALID));
        assertFalse(invalidJwtException.hasErrorCode(ErrorCodes.SIGNATURE_MISSING));

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(claimsJson);
        jwe.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        String encryptedOnlyJwt = jwe.getCompactSerialization();

        consumer = new JwtConsumerBuilder()
                .setMaxFutureValidityInMinutes(55)
                .setExpectedAudience("AUD")
                .setExpectedIssuer("ISS")
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaKeyFromJws.PRIVATE_KEY)
                .build();

        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(encryptedOnlyJwt, consumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.SIGNATURE_MISSING));
    }


    @Test
    public void wrappedNpeFromCustomValidatorTest() throws Exception
    {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzYW1lIiwiZXhwIjoxNDIwMDQ2ODE0fQ.LUViXhiMJRZa5veg6ayZCDQaIc0GfVDJDx-878WbFzg";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);

        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"Ek1bHgP9uYyEtB5-V6oAzT_wB4mUnvCpirPqO4MyFwE\"}");
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046767))
                .setExpectedAudience(false, "other", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .build();

        JwtContext process = consumer.process(jwt);
        assertThat(1, equalTo(process.getJoseObjects().size()));
        consumer.processContext(jwtContext);

        consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046768))
                .setExpectedAudience(false, "other", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .registerValidator(new Validator()
                {
                    @Override
                    public String validate(JwtContext jwtContext) throws MalformedClaimException
                    {
                        try
                        {
                            JwtClaims jcs = jwtContext.getJwtClaims();
                            List<String> audience = jcs.getAudience();
                            Iterator<String> iterator = audience.iterator();  // this will NPE
                            iterator.next();

                            return null;
                        }
                        catch (Exception e)
                        {
                            throw new RuntimeException("Something bad happened.", e);
                        }
                    }
                })
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext,consumer);
    }

    @Test
    public void wrappedNpeFromCustomErrorCodeValidatorTest() throws Exception
    {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzYW1lIiwiZXhwIjoxNDIwMDQ2ODE0fQ.LUViXhiMJRZa5veg6ayZCDQaIc0GfVDJDx-878WbFzg";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);

        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"Ek1bHgP9uYyEtB5-V6oAzT_wB4mUnvCpirPqO4MyFwE\"}");
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046767))
                .setExpectedAudience(false, "other", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .build();

        JwtContext process = consumer.process(jwt);
        assertThat(1, equalTo(process.getJoseObjects().size()));
        consumer.processContext(jwtContext);

        consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046768))
                .setExpectedAudience(false, "other", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .registerValidator(new ErrorCodeValidator()
                {
                    @Override
                    public Error validate(JwtContext jwtContext) throws MalformedClaimException
                    {
                        try
                        {
                            JwtClaims jcs = jwtContext.getJwtClaims();
                            List<String> audience = jcs.getAudience();
                            Iterator<String> iterator = audience.iterator();  // this will NPE
                            iterator.next();

                            return null;
                        }
                        catch (Exception e)
                        {
                            throw new RuntimeException("Something bad happened.", e);
                        }
                    }
                })
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext,consumer);
    }


    @Test
    public void someExpectedAndUnexpectedEx() throws Exception
    {
        // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-3.1
        String jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);


        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new VerificationKeyResolver()
                {
                    @Override
                    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException
                    {
                        throw new UnresolvableKeyException("Can't do it!");
                    }
                })
                .setEvaluationTime(NumericDate.fromSeconds(1300819372))
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

        consumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new VerificationKeyResolver()
                {
                    @Override
                    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException
                    {
                        throw new IllegalArgumentException("Stuff happens...");
                    }
                })
                .setEvaluationTime(NumericDate.fromSeconds(1300819372))
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);
    }

    @Test
    public void missingCtyInNested() throws Exception
    {
        // Nested jwt without "cty":"JWT" -> expect failure here as the cty is a MUST for nesting
        // setEnableLiberalContentTypeHandling() on the builder will enable a best effort to deal with the content even when cty isn't specified

        String jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsIngiOiIwRGk0VTBZQ0R2NHAtS2hETUZwUThvY0FsZzA2SEwzSHR6UldRbzlDLWV3IiwieSI6IjBfVFJjR1Y3Qy05d0xseFJZSExJOFlKTXlET2hWNW5YeHVPMGdRVmVxd0EiLCJjcnYiOiJQLTI1NiJ9fQ..xw5H8Kztd_sqzbXjt4GKUg.YNa163HLj7MwlvjzGihbOHnJ2PC3NOTnnvVOanuk1O9XFJ97pbbHHQzEeEwG6jfvDgdmlrLjcIJkSu1U8qRby7Xr4gzP6CkaDPbKwvLveETZSNdmZh37XKfnQ4LvKgiko6OQzyLYG1gc97kUOeikXTYVaYaeV1838Bi4q3DsIG-j4ZESg0-ePQesw56A80AEE3j6wXwZ4vqugPP9_ogZzkPFcHf1lt3-A4amNMjDbV8.u-JJCoakXI55BG2rz_kBlg";
        PublicJsonWebKey sigKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"loF6m9WAW_GKrhoh48ctg_d78fbIsmUb02XDOwJj59c\",\"y\":\"kDCHDkCbWjeX8DjD9feQKcndJyerdsLJ4VZ5YSTWCoU\",\"crv\":\"P-256\",\"d\":\"6D1C9gJsT9KXNtTNyqgpdyQuIrK-qzo0_QJOVe9DqJg\"}");
        PublicJsonWebKey encKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"PNbMydlpYRBFTYn_XDFvvRAFqE4e0EJmK6-zULTVERs\",\"y\":\"dyO9wGVgKS3gtP5bx0PE8__MOV_HLSpiwK-mP1RGZgk\",\"crv\":\"P-256\",\"d\":\"FIs8wVojHBdl7vkiZVnLBPw5S9lbn4JF2WWY1OTupic\"}");

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .setEnableLiberalContentTypeHandling()
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219088))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);

        consumer = new JwtConsumerBuilder()
                .setEnableLiberalContentTypeHandling()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219088))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        JwtContext ctx = consumer.process(jwt);
        consumer.processContext(jwtContext);

        for (JwtContext context : new JwtContext[] {ctx, jwtContext})
        {
            JwtClaims jwtClaims = context.getJwtClaims();
            assertThat("eh", equalTo(jwtClaims.getStringClaimValue("message")));
            List<JsonWebStructure> joseObjects = context.getJoseObjects();
            assertThat(2, equalTo(joseObjects.size()));
            assertTrue(joseObjects.get(0) instanceof JsonWebSignature);
            assertTrue(joseObjects.get(1) instanceof JsonWebEncryption);
        }
    }

    @Test
    public void missingCtyInNestedViaNimbusExample() throws Exception
    {
        // "Signed and encrypted JSON Web Token (JWT)" example JWT made from http://connect2id.com/products/nimbus-jose-jwt/examples/signed-and-encrypted-jwt
        // didn't have "cty":"JWT" at the time of writing (1/5/15 - https://twitter.com/__b_c/status/552105927512301568) but it made me think
        // allowing more liberal processing might be a good idea
        // keys and enc alg were changed from the example to produce this jwt
        final String jwt =
                "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
                "IAseIHBLnv7hFKz_V3-o-Of3Mf2DIGzFnSh_8sLZgujPaNIG8NlZmA." +
                "fwbuvibqYUlDzTXTtsB6yw." +
                "5T70ZVMqOTl4q_tYegL0bgJpT2wTUlSvnJ2QAB8KfpNO_J3StiK8oHvSmVOPOrCQJai_XffZGUpmAO2fnGnUajKmQpxm_iaJUZtzexwqeNlVzAr-swLUZDmW0lh3NgDB" +
                    "EAgY4khN7v1L_etToKuuEI6P-UGsg34BqaNuZEkj7ylsY1McZg73t5x9C4Q9dsBbsPLFPPUxxvA2abJhAq1Hew." +
                "D1hDq8pD6nQ42yvez-yjlQ\n";

        AesKey decryptionKey = new AesKey(new byte[16]);

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setDecryptionKey(decryptionKey)
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .setEnableLiberalContentTypeHandling()
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);

        final JwtConsumer consumer = new JwtConsumerBuilder()
                .setEnableLiberalContentTypeHandling() // this will try nested content as JOSE if JSON paring fails
                .setDecryptionKey(decryptionKey)
                .setVerificationKey(new AesKey(new byte[32]))
                .setEvaluationTime(NumericDate.fromSeconds(1420467806))
                .setExpectedIssuer("https://c2id.com")
                .setRequireIssuedAt()
                .build();

        JwtContext ctx = consumer.process(jwt);

        for (JwtContext context : new JwtContext[] {ctx, jwtContext})
        {
            JwtClaims jwtClaims = context.getJwtClaims();
            assertThat("alice", equalTo(jwtClaims.getSubject()));
            List<JsonWebStructure> joseObjects = context.getJoseObjects();
            assertThat(2, equalTo(joseObjects.size()));
            assertTrue(joseObjects.get(0) instanceof JsonWebSignature);
            assertTrue(joseObjects.get(1) instanceof JsonWebEncryption);
        }
    }

    @Test
    public void ctyValueVariationsInNested() throws Exception
    {
        // Nested jwt with variations on "cty":"JWT" like jwt, application/jwt, application/JWT ...

        PublicJsonWebKey sigKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"HVDkXtG_j_JQUm_mNaRPSbsEhr6gdK0a6H4EURypTU0\",\"y\":\"NxdYFS2hl1w8VKf5UTpGXh2YR7KQ8gSBIHu64W0mK8M\",\"crv\":\"P-256\",\"d\":\"ToqTlgJLhI7AQYNLesI2i-08JuaYm2wxTCDiF-VxY4A\"}");
        PublicJsonWebKey encKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"7kaETHB4U9pCdsErbjw11HGv8xcQUmFy3NMuBa_J7Os\",\"y\":\"FZK-vSMpKk9gLWC5wdFjG1W_C7vgJtdm1YfNPZevmCw\",\"crv\":\"P-256\",\"d\":\"spOxtF0qiKrrCTaUs_G04RISjCx7HEgje_I7aihXVMY\"}");

        String jwt;
        jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6ImFwcGxpY2F0aW9uL2p3dCIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJCOUhPbG82UV9LV0NiQjZLbk1RMDFfaHcyRXdaQWNEMmNucEdYYVl5WFBBIiwieSI6InJYS2s3VzM4UXhVOHl4YWZZc3NsUjFWU2JLbDI5T0FNSWxROFBCWXVZcUEiLCJjcnYiOiJQLTI1NiJ9fQ..LcIG9_bnPb43aaps32H6yQ.rsV7ItJWWfNafDJmeLHluKhiwmsU0Mlwut2jwD6y96KpjD-hz_5zBxpXtj6mk8yGZwg2L26XLo8npt_82bhKnMYqlKSRM-3ge2Deg5WPmBCx6Fj0NyCMnoR8oJTn-oxh0OHZICK_85Xz3GptopeA3Hj8ESdsJEI6D4WbXQ7HfGeg8ID9uvTaL8NGOHT4BGY0bB-6nl3qNIY5ULpg-a4a1ou5k9HnM6SRSpVRwpBBUsk.1vqvwv9XAzsQfvragyMXZQ";
        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .setEnableLiberalContentTypeHandling()
                .build();
        JwtContext jwtContext = firstPassConsumer.process(jwt);
        assertThat("eh", equalTo(jwtContext.getJwtClaims().getStringClaimValue("message")));
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219088))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        JwtContext context = consumer.process(jwt);
        JwtClaims jwtClaims = context.getJwtClaims();
        assertThat("eh", equalTo(jwtClaims.getStringClaimValue("message")));
        consumer.processContext(jwtContext);

        jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6ImFwcGxpY2F0aW9uL0pXVCIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJxelBlRUl0ZXJmQ0dhTFBpbDU3UmRudERHQVdwdVlBRGtVLUJubkkyTXowIiwieSI6ImNmWUxlc1dneGlfVndCdzdvSzNPT3dabGNrbVRCVmMzcEdnMTNRZ3V5WjQiLCJjcnYiOiJQLTI1NiJ9fQ..ftNMf4CqUSCq8p3L1Y7K1A.Z9K1YIJmSY9du5LUuSs0szCj1PUzq0ZnsEppT8yVPdGVDkDi0elEcsM8dCq8CvYrXG8OFuyp0s8dd2u_fIw4RjMc-aVMBT4ikWDmqb4CA17nC2Hxm6dZFPy3Xx3GnqjiGUIB2JiMOxj6mBZtTSvkKAUvs3Rh4G-87v2hJFpqdLSySqd-rQXL7Dhqxl0Cbu9nZFcYEIk58lpC0H2TN9aP5GtuQYa3BlNuEoEDzIcLhc4.N6VFQ0_UgNqyBsPLyE6MQQ";
        firstPassConsumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .setEnableLiberalContentTypeHandling()
                .build();
        jwtContext = firstPassConsumer.process(jwt);
        assertThat("eh", equalTo(jwtContext.getJwtClaims().getStringClaimValue("message")));
        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219095))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        context = consumer.process(jwt);
        jwtClaims = context.getJwtClaims();
        assertThat("eh", equalTo(jwtClaims.getStringClaimValue("message")));
        consumer.processContext(jwtContext);


        jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6Imp3dCIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJoTm5zTlRXZWN3TEVRUGVRMlFjZ05WSDJLX0dzTkFUZXNVaENhY2x2OVAwIiwieSI6ImI2V1lSR1V5Z1NBUGo5a0lFYktYTm5ZaDhEbmNrRXB2NDFYbUVnanA4VE0iLCJjcnYiOiJQLTI1NiJ9fQ..VGTURmPYERdJ7q9_5wlENA.91m_JN65XNlp9WsFHaHihhGB7soKNUdeBNpmODVcIiinhPClH00-GTMwfT08VmXEU2djW3Aw_eBAoU7rI_M0ovYbbmAy7UnVRUyCTbkGsQpv7OxYIznemMVMraFuHNmTAF_MU7oM4gPkqKzwuBa0uwd4JhN00bq-jEcLifMPgMvyGvfJ19SXAyrIVA4Otjuii347V5u1GwlB5VBqMiqtBnbMMzR1Fe3X-4-sEgT9BrM.4T3uLGa4Bm5_r-ZNKPzEWg";
        firstPassConsumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .setEnableLiberalContentTypeHandling()
                .build();
        jwtContext = firstPassConsumer.process(jwt);
        assertThat("eh", equalTo(jwtContext.getJwtClaims().getStringClaimValue("message")));
        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219099))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        context = consumer.process(jwt);
        jwtClaims = context.getJwtClaims();
        assertThat("eh", equalTo(jwtClaims.getStringClaimValue("message")));
        consumer.processContext(jwtContext);

        jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6ImpXdCIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJmYTlJVEh6cEROSG1uV2NDSDVvWGtFYjJ1SncwTXNOU2stQjdFb091WUEwIiwieSI6IkZ1U0RaVXdmb1EtQXB6dEFQRUc1dk40QmZRR2sxWnRMT0FzM1o0a19obmciLCJjcnYiOiJQLTI1NiJ9fQ..FmuORwLWIoNBbRh0XcBzJQ.pSr58DMuRstF3A6xj24yM4KvNgWxtb_QDKuldesTCD-R00BNFwIVx4F51VL5DwR54ITgBZBKdAT4pN6eM-td5VrWBCnSWxFjNrBoDnnRkDfFgq8OjOBaR7k_4zUk41bBikDZ0JOQDWuiaODYBk7PWq0mgotvLPbJ9oc7zfp6lbHqaYXjbzfuD56W_kDYO8zSjiZUGLcYgJDYnO3F8K-QhP02v-0OEpAGrm5SKKV3Txk.Ecojfru8KbkqIw4QvYS3qA";
        firstPassConsumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .setEnableLiberalContentTypeHandling()
                .build();
        jwtContext = firstPassConsumer.process(jwt);
        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420220122))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        context = consumer.process(jwt);
        jwtClaims = context.getJwtClaims();
        assertThat("eh", equalTo(jwtClaims.getStringClaimValue("message")));
        consumer.processContext(jwtContext);
    }

    @Test
    public void ctyRoundTrip() throws JoseException, InvalidJwtException, MalformedClaimException
    {
        JsonWebKeySet jwks = new JsonWebKeySet("{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"hk1\",\"alg\":\"HS256\",\"k\":\"RYCCH0Qai_7Clk_GnfBElTFIa5VJP3pJUDd8g5H0PKs\"}," +
                "{\"kty\":\"oct\",\"kid\":\"ek1\",\"alg\":\"A128KW\",\"k\":\"Qi38jqNMENlgKaVRbhKWnQ\"}]}");

        SimpleJwkFilter filter = new SimpleJwkFilter();
        filter.setKid("hk1", false);
        JsonWebKey hmacKey = filter.filter(jwks.getJsonWebKeys()).iterator().next();

        filter = new SimpleJwkFilter();
        filter.setKid("ek1", false);
        JsonWebKey encKey = filter.filter(jwks.getJsonWebKeys()).iterator().next();

        JwtClaims claims = new JwtClaims();
        claims.setSubject("subject");
        claims.setAudience("audience");
        claims.setIssuer("issuer");
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setNotBeforeMinutesInThePast(5);
        claims.setGeneratedJwtId();

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setPayload(claims.toJson());
        jws.setKey(hmacKey.getKey());
        jws.setKeyIdHeaderValue(hmacKey.getKeyId());
        String innerJwt = jws.getCompactSerialization();

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(encKey.getKey());
        jwe.setKeyIdHeaderValue(encKey.getKeyId());
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setPayload(innerJwt);
        String jwt = jwe.getCompactSerialization();

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(encKey.getKey())
                .setVerificationKey(hmacKey.getKey())
                .build();

        JwtContext jwtContext = jwtConsumer.process(jwt);
        assertThat("subject", equalTo(jwtContext.getJwtClaims().getSubject()));
        List<JsonWebStructure> joseObjects = jwtContext.getJoseObjects();
        JsonWebStructure outerJsonWebObject = joseObjects.get(joseObjects.size() - 1);
        Assert.assertTrue(outerJsonWebObject instanceof JsonWebEncryption);
        assertThat("JWT", equalTo(outerJsonWebObject.getContentTypeHeaderValue()));
        assertThat("JWT", equalTo(outerJsonWebObject.getHeader(HeaderParameterNames.CONTENT_TYPE)));
        assertThat("JWT", equalTo(outerJsonWebObject.getHeaders().getStringHeaderValue(HeaderParameterNames.CONTENT_TYPE)));
        JsonWebStructure innerJsonWebObject = joseObjects.get(0);
        Assert.assertTrue(innerJsonWebObject instanceof JsonWebSignature);
    }

    @Test
    public void nestedBackwards() throws Exception
    {
        // a JWT that's a JWE inside a JWS, which is unusual but legal
        String jwt = "eyJjdHkiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.ZXlKNmFYQWlPaUpFUlVZaUxDSmhiR2NpT2lKRlEwUklMVVZUSWl3aVpXNWpJam9pUVRFeU9FTkNReTFJVXpJMU5pSXNJbVZ3YXlJNmV5SnJkSGtpT2lKRlF5SXNJbmdpT2lKYVIwczNWbkZOUzNKV1VGcEphRXc1UkRsT05tTnpNV0ZhYlU5MVpqbHlUWGhtUm1kRFVURjFaREJuSWl3aWVTSTZJbTAyZW01VlQybEtjMnMwTlRaRVVWb3RjVTEzZEVKblpqQkRNVXh4VDB0dk5HYzNjakpGUTBkQllUZ2lMQ0pqY25ZaU9pSlFMVEkxTmlKOWZRLi4xSndRWThoVFJVczdUMFNpOWM1VE9RLkFOdUpNcFowTU1KLTBrbVdvVHhvRDlxLTA1YUxrMkpvRzMxLXdVZ01ZakdaaWZiWG96SDEzZGRuaXZpWXNtenhMcFdVNU1lQnptN3J3TExTeUlCdjB3LmVEb1lFTEhFWXBnMHFpRzBaeHUtWEE.NctFu0mNSArPnMXakIMQKagWyU4v7733dNhDNK3KwiFP2MahpfaH0LA7x0knRk0sjASRxDuEIW6UZGfPTFOjkw";

        PublicJsonWebKey sigKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"HVDkXtG_j_JQUm_mNaRPSbsEhr6gdK0a6H4EURypTU0\",\"y\":\"NxdYFS2hl1w8VKf5UTpGXh2YR7KQ8gSBIHu64W0mK8M\",\"crv\":\"P-256\",\"d\":\"ToqTlgJLhI7AQYNLesI2i-08JuaYm2wxTCDiF-VxY4A\"}");
        PublicJsonWebKey encKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"7kaETHB4U9pCdsErbjw11HGv8xcQUmFy3NMuBa_J7Os\",\"y\":\"FZK-vSMpKk9gLWC5wdFjG1W_C7vgJtdm1YfNPZevmCw\",\"crv\":\"P-256\",\"d\":\"spOxtF0qiKrrCTaUs_G04RISjCx7HEgje_I7aihXVMY\"}");

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();
        JwtContext jwtContext = firstPassConsumer.process(jwt);

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420226222))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        JwtContext ctx = consumer.process(jwt);
        consumer.processContext(jwtContext);

        for (JwtContext context : new JwtContext[] {ctx, jwtContext})
        {
            JwtClaims jwtClaims = context.getJwtClaims();
            assertThat("eh", equalTo(jwtClaims.getStringClaimValue("message")));
            List<JsonWebStructure> joseObjects = context.getJoseObjects();
            assertThat(2, equalTo(joseObjects.size()));
            assertTrue(joseObjects.get(0) instanceof JsonWebEncryption);
            assertTrue(joseObjects.get(1) instanceof JsonWebSignature);
        }

    }

    @Test
    public void tripleNesting() throws Exception
    {
        // a JWT that's a JWE inside a JWS, which is unusual but legal
        String jwt = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5Ijoiand0IiwicDJjIjo4MTkyLCJwMnMiOiJiWE13N0F3YUtITWZ4cWRNIn0.5Qo4mtR0E6AnTsiq-hcH9_RJoZwmWiMl0se_riEr1sdz2IXA-vCkrw.iA7lBH3Tzs4uIJVtekZEfg.jkdleffS8GIen_xt_g3QHAc0cat6UBAODpv6WLJ_ytMw-h0dtV0F77d7k1oWxBQ68Ff83v3Pxsyiqf6K9BQUVyzmI6rZafDStQm1IdTS-rvsiB4qDrx9juMqzu1udPy5N7JGs_CDV31Ky3fWEveAy4kBX46-axdyhP5XFg6xMfJ614mcf_bfo5hIJByZFwqNolNwsHLUTuiUBa4Mdg-tfob692-ox8B2c6w4RqRrLOVA_M3gENoxbLIJGL0WL1OkdQb7fyEsaMzR3urJL1t8LI5Q1pD8wjbiv4VKvc1BqoJSM0h9mLm_GNhTdQGPmevBwWVZ1k1tWJjQw0nU2eFZJi1STDGzK1GRDBD91rZSYD763WHADbxcqxrcri92jtyZrxB22pJXEgkpMlUkxqjCFATV20WSM8aSW4Od9Of9MCnrNTIby_3np4zEq5EpFEkVmH-9PzalKWo5gOHR8Zqnldyz6xcOamP34o_lEh5ddEwAFjGTlJWrDkssMeBjOog3_CXHZhutD9IfCKmIHu6Wk10XkELamiKPmNCe_CMDEdx6o6LrCtfyheOfgpDaZeZZc3Y-TF1o9J3RmCZqB-oHgLEc9mZQrGU6r5UZ4lYyfrAJl2y7Rya87LBGsUjSs7SuIyQKYkH5ek8j_9rhm_3nZhivDchkiWx5J3Pzso5Q3p6hjUfvhpgO2ywtnii45iINi5UAL6O8xqUhxZUJSoMxt1XKwx92bmC9kOoF1ljLm-w.VP_VFGef9SGdxoHCZ01FxQ";

        PublicJsonWebKey sigKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"HVDkXtG_j_JQUm_mNaRPSbsEhr6gdK0a6H4EURypTU0\",\"y\":\"NxdYFS2hl1w8VKf5UTpGXh2YR7KQ8gSBIHu64W0mK8M\",\"crv\":\"P-256\",\"d\":\"ToqTlgJLhI7AQYNLesI2i-08JuaYm2wxTCDiF-VxY4A\"}");
        final PublicJsonWebKey encKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"7kaETHB4U9pCdsErbjw11HGv8xcQUmFy3NMuBa_J7Os\",\"y\":\"FZK-vSMpKk9gLWC5wdFjG1W_C7vgJtdm1YfNPZevmCw\",\"crv\":\"P-256\",\"d\":\"spOxtF0qiKrrCTaUs_G04RISjCx7HEgje_I7aihXVMY\"}");
        final Key passwordIsTaco = new PbkdfKey("taco");

        DecryptionKeyResolver decryptionKeyResolver = new DecryptionKeyResolver()
        {
            @Override
            public Key resolveKey(JsonWebEncryption jwe, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException
            {
                return nestingContext.isEmpty() ? passwordIsTaco : encKey.getPrivateKey();
            }
        };

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setDecryptionKeyResolver(decryptionKeyResolver)
                .setJweAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();
        JwtContext jwtContext = firstPassConsumer.process(jwt);

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKeyResolver(decryptionKeyResolver)
                .setJweAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420229816))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        JwtContext ctx = consumer.process(jwt);
        consumer.processContext(jwtContext);

        for (JwtContext context : new JwtContext[] {ctx, jwtContext})
        {
            JwtClaims jwtClaims = context.getJwtClaims();
            assertThat("eh", equalTo(jwtClaims.getStringClaimValue("message")));
            List<JsonWebStructure> joseObjects = context.getJoseObjects();
            assertThat(3, equalTo(joseObjects.size()));
            assertTrue(joseObjects.get(2) instanceof JsonWebEncryption);
            assertTrue(joseObjects.get(1) instanceof JsonWebEncryption);
            assertTrue(joseObjects.get(0) instanceof JsonWebSignature);
        }

    }

    @Test
    public void testExplicitTyping() throws Exception
    {
        JwtClaims claims = new JwtClaims();
        claims.setSubject("subject");
        claims.setAudience("audience");
        claims.setIssuer("issuer");
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setNotBeforeMinutesInThePast(5);
        claims.setGeneratedJwtId();

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setPayload(claims.toJson());
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        String innerJwt = jws.getCompactSerialization();

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setPayload(innerJwt);
        String jwt = jwe.getCompactSerialization();

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey())
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .setExpectedType(false,"at+jwt")
                .build();

        JwtContext jwtContext = jwtConsumer.process(jwt);
        assertThat("subject", equalTo(jwtContext.getJwtClaims().getSubject()));

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey())
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .setExpectedType(true,"at+jwt")
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);


        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setPayload(claims.toJson());
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        innerJwt = jws.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setHeader(HeaderParameterNames.TYPE, "at+jwt");
        jwe.setPayload(innerJwt);
        jwt = jwe.getCompactSerialization();

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey())
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .setExpectedType(false,"at+jwt")
                .build();

        jwtContext = jwtConsumer.process(jwt);
        assertThat("subject", equalTo(jwtContext.getJwtClaims().getSubject()));

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey())
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .setExpectedType(true,"at+jwt")
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setPayload(claims.toJson());
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        jws.setHeader(HeaderParameterNames.TYPE, "at+jwt");
        innerJwt = jws.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setPayload(innerJwt);
        jwt = jwe.getCompactSerialization();

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey())
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .setExpectedType(false,"application/at+jwt")
                .build();

        jwtContext = jwtConsumer.process(jwt);
        assertThat("subject", equalTo(jwtContext.getJwtClaims().getSubject()));

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey())
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .setExpectedType(true,"at+jwt")
                .build();

        jwtContext = jwtConsumer.process(jwt);
        assertThat("subject", equalTo(jwtContext.getJwtClaims().getSubject()));

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey())
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .setExpectedType(true,"secevent+jwt")
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);


        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setPayload(claims.toJson());
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        jws.getHeaders().setObjectHeaderValue(HeaderParameterNames.TYPE, Arrays.asList("at+jwt","not+ok"));
        innerJwt = jws.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setPayload(innerJwt);
        jwt = jwe.getCompactSerialization();

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey())
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .setExpectedType(true,"at+jwt")
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey())
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .setExpectedType(true,"at+jwt")
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setPayload(claims.toJson());
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        jws.setHeader(HeaderParameterNames.TYPE, "");
        innerJwt = jws.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setPayload(innerJwt);
        jwt = jwe.getCompactSerialization();

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey())
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .setExpectedType(true,"at+jwt")
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("issuer")
                .setExpectedAudience("audience")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey())
                .setVerificationKey(ExampleRsaKeyFromJws.PUBLIC_KEY)
                .setExpectedType(true,"at+jwt")
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);
    }

    @Test
    public void testOnlyEncrypted() throws Exception
    {
        // there are legitimate cases where a JWT need only be encrypted but the majority of time a mac'd or signed JWS is needed
        // by default the JwtConsumer should not accept a JWE only JWT to protect against cases where integrity protection might
        // be accidentally inferred

        PublicJsonWebKey sigKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"HVDkXtG_j_JQUm_mNaRPSbsEhr6gdK0a6H4EURypTU0\",\"y\":\"NxdYFS2hl1w8VKf5UTpGXh2YR7KQ8gSBIHu64W0mK8M\",\"crv\":\"P-256\",\"d\":\"ToqTlgJLhI7AQYNLesI2i-08JuaYm2wxTCDiF-VxY4A\"}");
        PublicJsonWebKey encKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"7kaETHB4U9pCdsErbjw11HGv8xcQUmFy3NMuBa_J7Os\",\"y\":\"FZK-vSMpKk9gLWC5wdFjG1W_C7vgJtdm1YfNPZevmCw\",\"crv\":\"P-256\",\"d\":\"spOxtF0qiKrrCTaUs_G04RISjCx7HEgje_I7aihXVMY\"}");

        String jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJ3UXdIa1RUci1tUFpaZURDYU8wRjEwNi1NTkg0aFBfX0xrTW5MaElkTVhVIiwieSI6IkF4Ul9VNW1EN1FhMnFia3R5WS0tU1dsMng0N1gxTWJ5S2Rxb1JteUFVS1UiLCJjcnYiOiJQLTI1NiJ9fQ..oeYI_sIoU1LWIUw3z16V_g.J_BlS-qDJnAqw9wzngIQQioTbTGbyFnorVRq1WTO3leFXKKuBmqoWPHqoVSZdzsVeiFkI-F1DesY489MltwGYg.egjQH2w4oHpMgfjg8saXxQ";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();
        JwtContext jwtContext = firstPassConsumer.process(jwt);
        assertThat("eh", equalTo(jwtContext.getJwtClaims().getStringClaimValue("message")));

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219088))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219088))
                .setExpectedAudience("canada")
                .setDisableRequireSignature()
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        JwtContext context = consumer.process(jwt);
        JwtClaims jwtClaims = context.getJwtClaims();
        assertThat("eh", equalTo(jwtClaims.getStringClaimValue("message")));
        consumer.processContext(jwtContext);


        consumer = new JwtConsumerBuilder()
            .setDecryptionKey(encKey.getPrivateKey())
            .setVerificationKey(sigKey.getPublicKey())
            .setEvaluationTime(NumericDate.fromSeconds(1420219088))
            .setExpectedAudience("canada")
            .setDisableRequireSignature()
            .setEnableRequireIntegrity()  // this will ensure it fails b/c the JWT is only asymmetrically encrypted
            .setExpectedIssuer("usa")
            .setRequireExpirationTime()
            .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, consumer);
    }

    @Test
    public void encOnlyWithIntegrityIssues() throws Exception
    {
        String jwt = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..zWNzKpA-QA0BboVl02nz-A.oSy4V6cQ6EnuIMyazDCqc9jEZMC7k8LwLKkrC12Pf-wpFRyDtQjGdIZ_Ndq9JMAnrCbx0bgFSxjKISbXbcnHiA.QsGX3JhHP1Pwy4zQ8Ha9FQ";
        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"30WEMkbhwHPBkg_fIfm_4GuzIz5pPZB7_BSfI3dHbbQ\"}");
        DecryptionKeyResolver decryptionKeyResolver = new JwksDecryptionKeyResolver(Collections.singletonList(jsonWebKey));
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKeyResolver(decryptionKeyResolver)
                .setEvaluationTime(NumericDate.fromSeconds(1420230888))
                .setExpectedAudience("me")
                .setExpectedIssuer("me")
                .setRequireExpirationTime()
                .setDisableRequireSignature()
                .build();

        JwtClaims jwtClaims = consumer.processToClaims(jwt);
        assertThat("value", equalTo(jwtClaims.getStringClaimValue("name")));

        // change some things and make sure it fails
        jwt = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..zWNzKpA-QA0BboVl02nz-A.eyJpc3MiOiJtZSIsImF1ZCI6Im1lIiwiZXhwIjoxNDIwMjMxNjA2LCJuYW1lIjoidmFsdWUifQ.QsGX3JhHP1Pwy4zQ8Ha9FQ";
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);

        jwt = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..zWNzKpA-QA0BboVl02nz-A.u1D7JCpDFeRl69G1L-h3IRrmcOXiWLnhr23ugO2kkDqKVNcO1YQ4Xvl9Sag4aYOnkqUbqe6Wdz8KK3d9q178tA.QsGX3JhHP1Pwy4zQ8Ha9FQ";
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);
    }

    @Test
    public void hmacWithResolver() throws Exception
    {
        String jwt = "eyJraWQiOiJfMyIsImFsZyI6IkhTMjU2In0" +
                ".eyJpc3MiOiJmcm9tIiwiYXVkIjpbInRvIiwib3J5b3UiXSwiZXhwIjoxNDI0MDQxNTc0LCJzdWIiOiJhYm91dCJ9" +
                ".jgC4hWHd1C4kkYiVIbung4vg44bQOEv3JkGupnRrYDk";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();
        JwtContext jwtContext = firstPassConsumer.process(jwt);


        String json = "{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"_1\",  \"k\":\"9g99cnHIc3kMeR_JbwmAojgUlHIH0GoKz7COz9719x1\"}," +
                "{\"kty\":\"oct\",\"kid\":\"_2\",  \"k\":\"vvlp7BacRr-a9pOKK7BKxZo88u6cY2o9Lz6-P--_01p\"}," +
                "{\"kty\":\"oct\",\"kid\":\"_3\",\"k\":\"a991cccx6-7rP5p91nnHi3K-jcDjsFh1o34bIeWA081\"}]}";

        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(json);

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1424041569))
                .setExpectedAudience("to")
                .setExpectedIssuer("from")
                .setRequireSubject()
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(jsonWebKeySet.getJsonWebKeys()))
                .setRequireExpirationTime()
                .build();

        JwtContext ctx = consumer.process(jwt);
        consumer.processContext(jwtContext);

        for (JwtContext context : new JwtContext[] {ctx, jwtContext})
        {
            assertThat(1, equalTo(context.getJoseObjects().size()));
            assertThat("about", equalTo(context.getJwtClaims().getSubject()));
        }
    }

    @Test
    public void ifItWereAnIdTokenHint() throws InvalidJwtException, JoseException, MalformedClaimException
    {
        // an ID Token and JWKS from NRI-phpOIDC-Implicit-10-Apr-2015 http://openid.net/certification/ just 'cause it's nice to have JWT content produced elsewhere
        // this test was intended to explore some concepts around https://bitbucket.org/b_c/jose4j/issue/19 (skipping date aud checks and also an expected subject value)
        String keys = "{\n" +
                "\"keys\": [\n" +
                "  {\n" +
                "    \"e\": \"AQAB\",\n" +
                "    \"kid\": \"PHPOP-00\",\n" +
                "    \"kty\": \"RSA\",\n" +
                "    \"n\": \"lqjtB9h9j1yl5Y3pmyt0qRUuGnCSn6HWFXHdlUPwt2xanA8aP5MN5dlRJCVR_sR08pb4taIerowTZ7ShdSaWqkGAqwgJYhM0Nyvj_GO1XIYfWl2u49U8j1s" +
                "EFGDvNMNYQcX4RwaLU3lbavlYVHx_0W5gvw6XfEvkdWkPEbO3Ik1_cCySBxbaCxKszFP_yKCfRBbSQzrz_ZV6PMU6B0_OSknD7BRaogABdxPu79mUU-_Fk1XSA4gdRd5ccnX" +
                "6lXiF0ePiI2x7s-RdyrMMT4HrXMYlO7VxraUvK61bNOKuRqoV6K-OdJUbcgziRe0nEidgyOgRTXRgnRkyCp2eMkKXFw\"\n" +
                "}]}";

        String jwt = "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOlwvXC9jb25uZWN0Lm9wZW5pZDQudXM6NTQ0M1wvcGhwT3BcL29wLmp3ayIsImtpZCI6IlBIUE9QLTAwIn0" +
                ".eyJpc3MiOiJodHRwczpcL1wvY29ubmVjdC5vcGVuaWQ0LnVzOjU0NDNcL3BocE9wIiwic3ViIjoiZDRjMTEzOTE3NTA1MmRkNTE1ZmE5MzU4YTVjMmQ0YjRhNGF" +
                "kYTM2ZDgxNWJiODc4OWEwNDFhNDFmZmZmZGNlYSIsImF1ZCI6WyJSLVJ1ZmpTRFZHQ0dmZFRtSW9iZjJRIl0sImV4cCI6MTQyODQ0NjkwNSwiaWF0IjoxNDI4NDQ" +
                "2NjA1LCJub25jZSI6IlB1enhKSWtxdjZ6ciIsImF1dGhfdGltZSI6MTQyODQ0NTAxMH0" +
                ".WYh2Zn3oNys7VIa6bCCw9LcIPD95W5YP4XKiIBcY5gz0Ti3fiwslsbm1wGJB-nJA9AXi1cIywsZs94l7BKJdNdUiJQUuSFRuyHCCDY--7iELwWFIGXSzFkwjUsR" +
                "AAq9sMWqBO3qm01ganUH4Q9wFuSa-d6GA8ybMy3ymfV1OyNzVpTUqi9HWrRlAw0jUoTVGZA4p7qMzXgZfNF3pyankL2mmeb34ZhFk8S2IAZKFhRKuo0ORJRJ6_Fu" +
                "9Eq0DvfrvX1RJpA3MKkJ8aiD5N4fcUy7vzgQRCNqsgEaqC-i4-vlNN5uyKP5IUZW-hqh-c6rXVrM-8hpZtCM_Z76eRfv1VQ";
        // sub=d4c1139175052dd515fa9358a5c2d4b4a4ada36d815bb8789a041a41ffffdcea
        // aud=[R-RufjSDVGCGfdTmIobf2Q]
        // exp=1428446905 -> Apr 7, 2015 4:48:25 PM MDT

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(new JsonWebKeySet(keys).getJsonWebKeys()))
                .setAllowedClockSkewInSeconds(Integer.MAX_VALUE)
                .setExpectedSubject("d4c1139175052dd515fa9358a5c2d4b4a4ada36d815bb8789a041a41ffffdcea")
                .setExpectedAudience("R-RufjSDVGCGfdTmIobf2Q")
                .build();
        JwtContext jwtCtx = consumer.process(jwt);
        assertThat(jwtCtx.getJwtClaims().getSubject(), equalTo("d4c1139175052dd515fa9358a5c2d4b4a4ada36d815bb8789a041a41ffffdcea"));

        consumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(new JsonWebKeySet(keys).getJsonWebKeys()))
                .setAllowedClockSkewInSeconds(Integer.MAX_VALUE)
                .setExpectedSubject("NOOOOOOOOOOOOOOOOPE")
                .setExpectedAudience("R-RufjSDVGCGfdTmIobf2Q")
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);


        consumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(new JsonWebKeySet(keys).getJsonWebKeys()))
                .setAllowedClockSkewInSeconds(Integer.MAX_VALUE)
                .setSkipDefaultAudienceValidation()
                .build();
        jwtCtx = consumer.process(jwt);
        assertThat(jwtCtx.getJwtClaims().getAudience().iterator().next(), equalTo("R-RufjSDVGCGfdTmIobf2Q"));

        consumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(new JsonWebKeySet(keys).getJsonWebKeys()))
                .setAllowedClockSkewInSeconds(Integer.MAX_VALUE)
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);

        consumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(new JsonWebKeySet(keys).getJsonWebKeys()))
                .setAllowedClockSkewInSeconds(Integer.MAX_VALUE)
                .setExpectedAudience("no", "nope", "no way jose")
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);
    }

    @Test
    public void relaxDecryptionKeyValidation() throws Exception
    {
//        PublicJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(1024);
//        rsaJsonWebKey.setKeyId("acc");
//        OctetSequenceJsonWebKey octetSequenceJsonWebKey = OctJwkGenerator.generateJwk(256);
//        octetSequenceJsonWebKey.setKeyId("ltc");
//
//        JsonWebKeySet jwks = new JsonWebKeySet(rsaJsonWebKey, octetSequenceJsonWebKey);
//        System.out.println(jwks.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
//
//        JwtClaims jwtClaims = new JwtClaims();
//        jwtClaims.setAudience("a");
//        jwtClaims.setIssuer("i");
//        jwtClaims.setExpirationTimeMinutesInTheFuture(10);
//        jwtClaims.setSubject("s");
//        jwtClaims.setNotBeforeMinutesInThePast(1);
//
//        System.out.println(jwtClaims);
//
//        JsonWebSignature jws = new JsonWebSignature();
//        jws.setPayload(jwtClaims.toJson());
//        jws.setKey(octetSequenceJsonWebKey.getKey());
//        jws.setKeyIdHeaderValue(octetSequenceJsonWebKey.getKeyId());
//        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
//        String jwsCompactSerialization = jws.getCompactSerialization();
//
//        System.out.println(jwsCompactSerialization);
//
//        JsonWebEncryption jwe = new JsonWebEncryption();
//        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
//        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
//        jwe.setKey(rsaJsonWebKey.getPublicKey());
//        jwe.setDoKeyValidation(false);
//        jwe.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
//        jwe.setPayload(jwsCompactSerialization);
//        jwe.setContentTypeHeaderValue("JWT");
//        String jweCompactSerialization = jwe.getCompactSerialization();
//
//        System.out.println(jweCompactSerialization);


        String jwt = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiJhY2MiLCJjdHkiOiJKV1QifQ" +
                ".KrukndaF2sHb3Y0r311rrYmCrXco-99ZIQ3iLjvCVbbow5MppRTK4DPJUShcndfcIVIFXMYSLGvIJwf39yZRJJ_EvBFnqhOUeCAsUHLGO1yxoQ619jmSh4bCaIicLYeivKaVSQN4Ezc5fvg-Nnv6TBIIgHuWMDU2Ztd96DJRokc" +
                ".wMg2Eb8izCOUnACqdrcPQA" +
                ".quFKSN7xQoMJzaYFBVwykQZ8zB3hpW8HtK7pm-4Ggzorno_K-eBQ7fXjRmJ1Jw-kCcmUa8flpnQqpL9jurtlz7DC1ABe0vm2ZkHoJluB6QeSr60Y9rP7kyy_rd3blXT_7t6Wgowo8MumXrrUUxxEQJgXvCmKbd-Rw9sK5jAHEug3zztLXHOX0O0QoxDzTJOsSRtodsu7bTJa-ADvPmK9e0Xp06NRqvx7WuJGKlq3cwQ" +
                ".DL6yaCdiOUcViN-eZVIwOA";

        JsonWebKeySet jwks = new JsonWebKeySet("{\"keys\":[" +
                "{\"kty\":\"RSA\",\"kid\":\"acc\",\"n\":\"pkRsP8W09WkolK85OQlq6XTQEoRsulNY6vQsJMluOPErKIOJp6K4cgg5n6Y9NXnswUt0n5suxqlKDHmRRQgU9BGBcqptmCog-0KQKvTqUQJmtDviRTu1aO12Zz_ATEszf8rvPt795xaFvDycCA2YS87lkdIET2ap2qrHCfeWlkk\"," +
                "\"e\":\"AQAB\",\"d\":\"MnNknV0ycZz9EVCx_lqbNEebs2K3UzpjKrf4hRkR9vlG7T4skM9RRFi2k3jv7cAXVPe-ZYfDA8jujSZ-LAItyPwIO-pbtIeXrKQtvLgP4igsfDMCmvRvNmUuV93Gy9fMBVhEGK_xxVQtJWbdgZsk_v2kMUkX4W2WS_Mbo3YHCwE\"," +
                "\"p\":\"2BBdLVoi6DP-5JJyTCxdBbaKUjQvVPHXlcqNdaKf2949Nze7IpLoPtkCTVVlTtEvAhYGxuI1i101fK4hGW_IcQ\",\"q\":\"xP_Mg7_SNlzg0eyCzK09mKdagOFfoHKIMoJb9qzOAENnIjt67hpxd7x2h45pX4HM7ObU_1OAl9IYvTqUPhPXWQ\"," +
                "\"dp\":\"ljx6rchZMWDGQiVaeID4hbpx38sNhmFLaIqZZkyYH4gexMBpzRadiuXWZfOVKALoTukF-VDdrnQ3duSVe1xw4Q\",\"dq\":\"Q23K8s2VhkYELdZmbuhdTQL7V2HM-X46YA9-qtA7MpvfkTgKu7URYYqAh6WXK7miCvR3s21BdrXTAfIrC5R_AQ\"," +
                "\"qi\":\"iaHGlWvmsQvWyZ5GdAar0WOJi_CNTGCzv9SaVnA83I1ewXvKejYMnzLjetPbopxE2enVicnvjlrDaihJbZ5TYA\"}" +
                ",{\"kty\":\"oct\",\"kid\":\"ltc\",\"k\":\"vJRXGLSNo-jggR8o5yxjzrm_82w-35rpnve0JzEr2sw\"}" +
                "]}");

        VerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());
        DecryptionKeyResolver decryptionKeyResolver = new JwksDecryptionKeyResolver(jwks.getJsonWebKeys());

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1432324168))
                .setExpectedAudience("a")
                .setExpectedIssuer("i")
                .setExpectedSubject("s")
                .setRequireExpirationTime()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setDecryptionKeyResolver(decryptionKeyResolver)
                .build();

         SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer); // fail b/c the RSA key is too small

        jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1432324168))
                .setExpectedAudience("a")
                .setExpectedIssuer("i")
                .setExpectedSubject("s")
                .setRequireExpirationTime()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setDecryptionKeyResolver(decryptionKeyResolver)
                .setRelaxDecryptionKeyValidation()  // be more relaxed here to allow the 1024 bit RSA key
                .build();

        JwtClaims claims = jwtConsumer.processToClaims(jwt);
        assertThat(claims.getClaimsMap().size(), equalTo(5));
    }

    @Test
    public void relaxVerificationKeyValidation() throws Exception
    {
//        OctetSequenceJsonWebKey octetSequenceJsonWebKey = OctJwkGenerator.generateJwk(128);
//        octetSequenceJsonWebKey.setKeyId("esc");
//
//        JsonWebKeySet jwks = new JsonWebKeySet(octetSequenceJsonWebKey);
//        System.out.println(jwks.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
//
//        JwtClaims jwtClaims = new JwtClaims();
//        jwtClaims.setAudience("a");
//        jwtClaims.setIssuer("i");
//        jwtClaims.setExpirationTimeMinutesInTheFuture(10);
//        jwtClaims.setSubject("s");
//        jwtClaims.setNotBeforeMinutesInThePast(1);
//
//        System.out.println(jwtClaims);
//
//        JsonWebSignature jws = new JsonWebSignature();
//        jws.setPayload(jwtClaims.toJson());
//        jws.setKey(octetSequenceJsonWebKey.getKey());
//        jws.setKeyIdHeaderValue(octetSequenceJsonWebKey.getKeyId());
//        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
//        jws.setDoKeyValidation(false);
//        String jwsCompactSerialization = jws.getCompactSerialization();
//
//        System.out.println(jwsCompactSerialization);

        String jwt = "eyJraWQiOiJlc2MiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhIiwiaXNzIjoiaSIsImV4cCI6MTQzMjMyNTQ5Niwic3ViIjoicyIsIm5iZiI6MTQzMjMyNDgzNn0.16LpzAZyBcokZ4aUaXHn5yN0xQ1zpmLyJVFHu6nH1zY";
        JsonWebKeySet jwks = new JsonWebKeySet("{\"keys\":[{\"kty\":\"oct\",\"kid\":\"esc\",\"k\":\"dbwsHvQsXoZiWpulhZA8dg\"}]}");

        VerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1432324836))
                .setExpectedAudience("a")
                .setExpectedIssuer("i")
                .setExpectedSubject("s")
                .setRequireExpirationTime()
                .setVerificationKeyResolver(verificationKeyResolver)
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer); // fail b/c the HMAC key is too small

        jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1432324836))
                .setExpectedAudience("a")
                .setExpectedIssuer("i")
                .setExpectedSubject("s")
                .setRequireExpirationTime()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setRelaxVerificationKeyValidation()  // be more relaxed here to allow the smaller key
                .build();

        JwtClaims claims = jwtConsumer.processToClaims(jwt);
        assertThat(claims.getClaimsMap().size(), equalTo(5));
    }

    @Test
    public void skipAllDefaultValidators() throws Exception
    {
//        OctetSequenceJsonWebKey octetSequenceJsonWebKey = OctJwkGenerator.generateJwk(256);
//        octetSequenceJsonWebKey.setKeyId("xxc");
//
//        JsonWebKeySet jwks = new JsonWebKeySet(octetSequenceJsonWebKey);
//        System.out.println(jwks.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
//
//        JwtClaims jwtClaims = new JwtClaims();
//        jwtClaims.setAudience("a");
//        jwtClaims.setIssuer("i");
//        jwtClaims.setExpirationTimeMinutesInTheFuture(10);
//        jwtClaims.setSubject("s");
//        jwtClaims.setNotBeforeMinutesInThePast(1);
//
//        System.out.println(jwtClaims);
//
//        JsonWebSignature jws = new JsonWebSignature();
//        jws.setPayload(jwtClaims.toJson());
//        jws.setKey(octetSequenceJsonWebKey.getKey());
//        jws.setKeyIdHeaderValue(octetSequenceJsonWebKey.getKeyId());
//        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
//        jws.setDoKeyValidation(false);
//        String jwsCompactSerialization = jws.getCompactSerialization();
//
//        System.out.println(jwsCompactSerialization);

        String jwt = "eyJraWQiOiJ4eGMiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhIiwiaXNzIjoiaSIsImV4cCI6MTQzMjMyNzE5NSwic3ViIjoicyIsIm5iZiI6MTQzMjMyNjUzNX0.zfBXCLSysVxY-zT4DNCLXS7IyfKkYv7kCIUKxdIGxdI";
        JsonWebKeySet jwks = new JsonWebKeySet("{\"keys\":[{\"kty\":\"oct\",\"kid\":\"xxc\",\"k\":\"7bLZdrROsprHkX75gCjKLeGj4brDf7TFtcr2h1F_nfc\"}]}");

        VerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(verificationKeyResolver)
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer); // fail b/c exp and aud


        jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setSkipAllDefaultValidators()
                .build();
        JwtClaims claims = jwtConsumer.processToClaims(jwt);  // this will work 'cause no claims validation is happening
        assertThat(claims.getClaimsMap().size(), equalTo(5));


        Validator customValidator = new Validator()
        {
            @Override
            public String validate(JwtContext jwtContext) throws MalformedClaimException
            {
                return (jwtContext.getJwtClaims().getIssuer().equals("i")) ? "i isn't okay as an issuer" : null;
            }
        };

        jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setSkipAllDefaultValidators()
                .registerValidator(customValidator)
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer); // make sure fail w/ custom validator b/c setSkipAllDefaultValidators runs any that were registered

        jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setSkipAllValidators()
                .registerValidator(customValidator)
                .build();
        claims = jwtConsumer.processToClaims(jwt);  // this will work 'cause no claims validation is happening due to setSkipAllValidators
        assertThat(claims.getClaimsMap().size(), equalTo(5));

        // setSkipAllDefaultValidators makes more sense than setSkipAllValidators but I started with setSkipAllValidators and don't want to change that behaviour and accidentally break someone
    }

    @Test
    public void googleIdTokensAndMultipleIssuers() throws JoseException, InvalidJwtException, MalformedClaimException
    {
        // https://www.googleapis.com/oauth2/v3/certs
        String jwksUriContent = "{\n" +
                " \"keys\": [\n" +
                "  {\n" +
                "   \"kty\": \"RSA\",\n" +
                "   \"alg\": \"RS256\",\n" +
                "   \"use\": \"sig\",\n" +
                "   \"kid\": \"6faa4e9ec30030784b8942606fb61762ada97253\",\n" +
                "   \"n\": \"mQFT4IjnxC1yhSqumpxY-BcRNfwfkqbYVHfIJNxTdQiTdVFizapkQEuRvuLLXVBZcTKJftQNEZ4RHbXTJFq5l6MoDPMSHCH_MBLjkYhrHLSdLpmJRb047PgbjVYCRbAEuuf" +
                "-ejwLPRTdrPCaC3vEm4-UaJgNoVnKpQKCCl4LRhaSdIXrmAv-AKwq7RmTYwP84UcbL379xhvUUnA3BMrNzSeyEPPUeOJO5eAprcSGQztFE2FuqXFPrOMkD_WK9El21UHEwPzpUD-OvTL4LC" +
                "9w1dImfzU5SC3g1DBz0N3GZawWGoNSH5x6gYereKVmfdPmX6zbV-Lb4mv3Kh8hki2jOw\",\n" +
                "   \"e\": \"AQAB\"\n" +
                "  },\n" +
                "  {\n" +
                "   \"kty\": \"RSA\",\n" +
                "   \"alg\": \"RS256\",\n" +
                "   \"use\": \"sig\",\n" +
                "   \"kid\": \"104625465f6d4c7d214e3326913c5a5e4505699c\",\n" +
                "   \"n\": \"qysmso1d2qSWZzMWqmfDHc7vR75gS5MCv1eMhzOrs9axnpyId0TzUQl2o2Su2o0mMtEfiirEhPFHPbFLVX8xc9SJPF6HCTQVS120_1NIjBhkZeiXzW4J6V8HSgL_9gwIwaMj" +
                "JYv7MB5SpHYIuIrdiUliaxPBCt2xZKqvAcU7G33kvOi7XneQaFxQrj2yxD9WkX-fRWS_0oZwN9-SBtQ84LJHYSgS-nclK2uuSHBI5_OV14r6A5boRU7Hjq7DLDjz7XxxXGqwbU5KYGjBP-_v" +
                "3OKvWKyTH4zQr24pmGVeTxZ_R1XAitO73cYtqqa25UvKGvFfam8-6VSVjrPC5tFayQ\",\n" +
                "   \"e\": \"AQAB\"\n" +
                "  },\n" +
                "  {\n" +
                "   \"kty\": \"RSA\",\n" +
                "   \"alg\": \"RS256\",\n" +
                "   \"use\": \"sig\",\n" +
                "   \"kid\": \"d2d90509119f4e7303c5d00647a27f340f928888\",\n" +
                "   \"n\": \"39CuERDfCaxMvPM_8cu4wj_decxS7OpB7NPUfO4LiH7e3ZXU83SLsSr4roDwgwlx_he4gFOnEjZ10aastOropI7Mx8Aw-EcHyOKgg1dzk3CjunlLc4vMbqSdRbN_UnQWWa-a" +
                "YgVGOloXDuVT4LegKrgQpKwUJ-IfaTIVGf5kQhYtJgC-LTgBpu99M2wVFQGLLqurNdbTIomWv75whFli3VRuTcb-0lBq0M9D6d3VEn747YS1c8i38e0Kbd9-XcPHWLCmi0tG0RmJ1iWB9rGi" +
                "ima9rU-MmIs7oaMg3COFoqtXiCzAWdVp-lsWIa9d7Ci3aykJpBK2AZ-xjMUg7UZfHw\",\n" +
                "   \"e\": \"AQAB\"\n" +
                "  }\n" +
                " ]\n" +
                "}";

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1470854975))
                .setExpectedAudience("407408718192.apps.googleusercontent.com")
                .setExpectedIssuers(true, "https://accounts.google.com", "accounts.google.com")
                .setRequireSubject()
                .setRequireExpirationTime()
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(new JsonWebKeySet(jwksUriContent).getJsonWebKeys()))
                .build();


        // id token from https://accounts.google.com/o/oauth2/v2/auth has iss of https://accounts.google.com
        String jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwNDYyNTQ2NWY2ZDRjN2QyMTRlMzMyNjkxM2M1YTVlNDUwNTY5OWMifQ" +
                ".eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5" +
                "jb20iLCJzdWIiOiIxMDkzNTgzODE5Nzc2Mzg1MTcyODYiLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20" +
                "iLCJub25jZSI6ImZmcyIsImlhdCI6MTQ3MDg1NDg3MCwiZXhwIjoxNDcwODU4NDcwfQ" +
                ".PeIZ-N5SHIwdYBL-LgCxY3wuKeoarfwbiKiVegEB6sD7UB96j-eNTreTCTSywj8DQIOvegEyaxhCHZaVJ7mIwRsTnlstUUR6soe8tu2gjhO" +
                "qTkqaYeKAqbPov7-M9afY-MgvHe4xndIEh1So54bf1lJ_PzrJnCXHBaCobhs4clhPMqZuy9XlPaZMDJPDfVsbPdHqV6Uxt4KTQQECI_i9j4wP6ks5g1" +
                "lbKTpyKrXOm4n-25zp1_HlKSEb7kqd-1zTvEz2W0tq741b2STnrZ1RW13Gh4cZzOVSRvqo2oNNq286R22JEHVWjBuR01OiasgyY8QcYPI_8F-K9cAhsNJhcg";

        JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
        assertThat("ffs", equalTo(jwtClaims.getStringClaimValue("nonce")));
        assertThat("https://accounts.google.com", equalTo(jwtClaims.getIssuer()));

        // id token from https://accounts.google.com/o/oauth2/auth has iss of accounts.google.com
        jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZmYWE0ZTllYzMwMDMwNzg0Yjg5NDI2MDZmYjYxNzYyYWRhOTcyNTMifQ" +
                ".eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXVkIjoiNDA3NDA4NzE4MTkyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA" +
                "5MzU4MzgxOTc3NjM4NTE3Mjg2IiwiYXpwIjoiNDA3NDA4NzE4MTkyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQ" +
                "uY29tIiwibm9uY2UiOiJmZnMiLCJpYXQiOjE0NzA4NTU5ODMsImV4cCI6MTQ3MDg1OTU4M30" +
                ".lxxxAqApJvQEubL4FXHcJvsG9wu3kxWcCFZTt6OMjB9j_P1KNu6CAgRn-E9T-ACJGpqVjR0GoODlVIdZHF" +
                "2wnntOxv9hNY7huSPDeWy661nCYuBMJRMcIqx6Hl7M7fCtTEu0ERYRHy9L9-tWnWUyxz3aZVvWQR1LB6P2Z" +
                "wgv1aZPptoTO5GxyNVIQApHq-BbNtaVd6qa3XDFrLMyq84FYwgGJzCjoM9Vu3YN4S4DZs6M59FC_hM" +
                "qldOqrkOCDs0Z49-q1pRS3WDZP_5r6gF9AKzyoB2TuEjMGrSHzp3l8YLuzHVCH8gQkiS9uzJESrEbYP9cr5AgMB5e4WGd0n1pXQ";
        jwtClaims = jwtConsumer.processToClaims(jwt);
        assertThat("ffs", equalTo(jwtClaims.getStringClaimValue("nonce")));
        assertThat("accounts.google.com", equalTo(jwtClaims.getIssuer()));
    }


    @Test
    public void roundTripWithMoreLiveDateChecks() throws Exception
    {
        OctetSequenceJsonWebKey octetSequenceJsonWebKey = OctJwkGenerator.generateJwk(256);
        octetSequenceJsonWebKey.setKeyId("ltc");

        JsonWebKeySet jwks = new JsonWebKeySet(octetSequenceJsonWebKey);

        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setAudience("a");
        jwtClaims.setIssuer("i");
        jwtClaims.setExpirationTimeMinutesInTheFuture(2);
        jwtClaims.setSubject("s");
        jwtClaims.setNotBeforeMinutesInThePast(2);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(jwtClaims.toJson());
        jws.setKey(octetSequenceJsonWebKey.getKey());
        jws.setKeyIdHeaderValue(octetSequenceJsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        String jwt = jws.getCompactSerialization();

        VerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setExpectedAudience("a")
                .setExpectedIssuer("i")
                .setExpectedSubject("s")
                .setRequireExpirationTime()
                .setVerificationKeyResolver(verificationKeyResolver)
                .build();
        JwtClaims claims = jwtConsumer.processToClaims(jwt);
        assertThat(claims.getClaimsMap().size(), equalTo(5));

        jwtClaims = new JwtClaims();
        jwtClaims.setAudience("a");
        jwtClaims.setIssuer("i");
        jwtClaims.setExpirationTimeMinutesInTheFuture(-1);
        jwtClaims.setSubject("s");
        jwtClaims.setNotBeforeMinutesInThePast(3);
        jws = new JsonWebSignature();
        jws.setPayload(jwtClaims.toJson());
        jws.setKey(octetSequenceJsonWebKey.getKey());
        jws.setKeyIdHeaderValue(octetSequenceJsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jwt = jws.getCompactSerialization();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);

        jwtClaims = new JwtClaims();
        jwtClaims.setAudience("a");
        jwtClaims.setIssuer("i");
        jwtClaims.setExpirationTimeMinutesInTheFuture(-1);
        jwtClaims.setSubject("s");
        jws = new JsonWebSignature();
        jws.setPayload(jwtClaims.toJson());
        jws.setKey(octetSequenceJsonWebKey.getKey());
        jws.setKeyIdHeaderValue(octetSequenceJsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jwt = jws.getCompactSerialization();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);

        jwtClaims = new JwtClaims();
        jwtClaims.setAudience("a");
        jwtClaims.setIssuer("i");
        jwtClaims.setExpirationTimeMinutesInTheFuture(20);
        jwtClaims.setSubject("s");
        jwtClaims.setNotBeforeMinutesInThePast(-4);
        jws = new JsonWebSignature();
        jws.setPayload(jwtClaims.toJson());
        jws.setKey(octetSequenceJsonWebKey.getKey());
        jws.setKeyIdHeaderValue(octetSequenceJsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jwt = jws.getCompactSerialization();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);

        jwtClaims = new JwtClaims();
        jwtClaims.setAudience("a");
        jwtClaims.setIssuer("i");
        jwtClaims.setExpirationTimeMinutesInTheFuture(1);
        jwtClaims.setSubject("s");
        jws = new JsonWebSignature();
        jws.setPayload(jwtClaims.toJson());
        jws.setKey(octetSequenceJsonWebKey.getKey());
        jws.setKeyIdHeaderValue(octetSequenceJsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jwt = jws.getCompactSerialization();
        claims = jwtConsumer.processToClaims(jwt);
        assertThat(claims.getClaimsMap().size(), equalTo(4));
    }

    @Test
    public void someIatOverflowsOrNearOnes()  throws Exception
    {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireIssuedAt()
                .setIssuedAtRestrictions(Integer.MAX_VALUE,Integer.MAX_VALUE)
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setEvaluationTime(NumericDate.fromSeconds(Long.MAX_VALUE/1000))
                .build();

        String c = "{\"iat\":9223372036854775808,\"jti\":\"meh123\",\"etc.\":\"etc., etc., etc...\"}"; // long max + 1
        String jwt = signClaims(c);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MALFORMED_CLAIM);

        c = "{\"iat\":25113002000004770000,\"jti\":\"meh123\",\"etc.\":\"etc., etc., etc...\"}"; // > long max
        jwt = signClaims(c);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MALFORMED_CLAIM);

        c = "{\"iat\":-9223372036854775809,\"jti\":\"meh123\",\"etc.\":\"etc., etc., etc...\"}"; // long min - 1
        jwt = signClaims(c);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MALFORMED_CLAIM);

        c = "{\"iat\":-77261600013501300000000,\"jti\":\"meh123\",\"etc.\":\"etc., etc., etc...\"}"; // < long min
        jwt = signClaims(c);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MALFORMED_CLAIM);

        long iat = Long.MAX_VALUE;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_FUTURE);

        iat = Long.MAX_VALUE/1000 + 67281;
        jwt = iatTestingJwt(iat);
        JwtClaims claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));

        iat = Long.MIN_VALUE;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MISCELLANEOUS);


        jwtConsumer = new JwtConsumerBuilder()
                .setRequireIssuedAt()
                .setIssuedAtRestrictions(60,60)
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setEvaluationTime(NumericDate.fromSeconds(Long.MAX_VALUE))
                .build();

        iat = Long.MAX_VALUE;
        jwt = iatTestingJwt(iat);
        claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));

        iat = Long.MIN_VALUE;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MISCELLANEOUS);

        jwtConsumer = new JwtConsumerBuilder()
                .setRequireIssuedAt()
                .setIssuedAtRestrictions(Integer.MAX_VALUE,Integer.MAX_VALUE)
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setEvaluationTime(NumericDate.fromSeconds(Long.MAX_VALUE))
                .setAllowedClockSkewInSeconds(Integer.MAX_VALUE)
                .build();

        iat = Long.MAX_VALUE;
        jwt = iatTestingJwt(iat);
        claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));

        iat = Long.MIN_VALUE;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MISCELLANEOUS);

        jwtConsumer = new JwtConsumerBuilder()
                .setRequireIssuedAt()
                .setIssuedAtRestrictions(10,10)
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setEvaluationTime(NumericDate.fromSeconds(0))
                .setAllowedClockSkewInSeconds(Integer.MAX_VALUE)
                .build();

        iat = Long.MAX_VALUE;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_FUTURE);

        iat = Long.MIN_VALUE;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MISCELLANEOUS);
    }

    @Test
    public void someOtherOverflowsOrNearOnes() throws Exception
    {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setEvaluationTime(NumericDate.fromSeconds(Long.MAX_VALUE - (62L * Integer.MAX_VALUE)))
                .setMaxFutureValidityInMinutes(Integer.MAX_VALUE)
                .setAllowedClockSkewInSeconds(Integer.MAX_VALUE)
                .build();

        String jwt = dateTestingJwt(null, Long.MAX_VALUE - (62L * Integer.MAX_VALUE) + 7L, Long.MAX_VALUE - (61L * Integer.MAX_VALUE) );
        JwtClaims claims = jwtConsumer.processToClaims(jwt);
        assertThat(4 , equalTo(claims.getClaimsMap().size()));

        jwt = signClaims("{\"nbf\":-1239223372036854775808,\"iat\":1571322100,\"exp\":9223372036854775807,\"jti\":\"meh123\"}");
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MALFORMED_CLAIM);

        jwt = signClaims("{\"nbf\":1571322100,\"iat\":12345678900000000000,\"exp\":12345678900000000009,\"jti\":\"meh123\"}");
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MALFORMED_CLAIM);

        jwt = signClaims("{\"nbf\":1571322100,\"iat\":1571322111,\"exp\":157132210009188371766311111,\"jti\":\"meh123\"}");
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MALFORMED_CLAIM);

        jwt = dateTestingJwt(null, null, Long.MAX_VALUE);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.EXPIRATION_TOO_FAR_IN_FUTURE);

        jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setEvaluationTime(NumericDate.fromSeconds(Long.MAX_VALUE - 15))
                .setMaxFutureValidityInMinutes(35)
                .setAllowedClockSkewInSeconds(30)
                .build();

        jwt = dateTestingJwt(-1L, null, Long.MAX_VALUE - 5);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MISCELLANEOUS); // overflow in adding with Skew and eval time when nbf is there

        jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setEvaluationTime(NumericDate.fromSeconds(Long.MIN_VALUE + 1000))
                .setAllowedClockSkewInSeconds(6000)
                .build();

        jwt = dateTestingJwt(null, null, 1572322100L);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MISCELLANEOUS);

        jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setEvaluationTime(NumericDate.fromSeconds(Long.MIN_VALUE + 70))
                .setAllowedClockSkewInSeconds(65)
                .setMaxFutureValidityInMinutes(1)
                .build();

        jwt = dateTestingJwt(null, null, Long.MIN_VALUE + 10);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MISCELLANEOUS);

        jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setEvaluationTime(NumericDate.fromSeconds(-10))
                .setMaxFutureValidityInMinutes(1)
                .build();

        jwt = dateTestingJwt(null, null, Long.MAX_VALUE);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.MISCELLANEOUS);
    }


    @Test
    public void iatReasonableness() throws Exception
    {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireIssuedAt()
                .setIssuedAtRestrictions(0,60)
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setEvaluationTime(NumericDate.fromSeconds(1571322100))
                .build();

        long iat = 1571322100;
        String jwt = iatTestingJwt(iat);
        JwtClaims claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));

        iat = 1571322099;
        jwt = iatTestingJwt(iat);
        claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));

        iat = 1571322043;
        jwt = iatTestingJwt(iat);
        claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));

        iat = 1571322040;
        jwt = iatTestingJwt(iat);
        claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));

        iat = 1571322039;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_PAST);

        iat = 1570321001;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_PAST);

        iat = 12345;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_PAST);

        iat = 0;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_PAST);

        iat = -938763;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_PAST);

        iat = Integer.MIN_VALUE - 88L;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_PAST);

        iat = 1571322101;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_FUTURE);

        iat = 1571322177;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_FUTURE);

        iat = Integer.MAX_VALUE;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_FUTURE);

        iat = 7700000007L;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_FUTURE);

        jwtConsumer = new JwtConsumerBuilder()
                .setRequireIssuedAt()
                .setIssuedAtRestrictions(10,120)
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setEvaluationTime(NumericDate.fromSeconds(1571322100))
                .build();

        iat = 1571322100;
        jwt = iatTestingJwt(iat);
        claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));

        iat -= 120;
        jwt = iatTestingJwt(iat);
        claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));

        iat -= 1;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_PAST);

        iat = 1571322105;
        jwt = iatTestingJwt(iat);
        claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));

        iat = 1571322110;
        jwt = iatTestingJwt(iat);
        claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));

        iat = 1571322111;
        jwt = iatTestingJwt(iat);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(jwt, jwtConsumer, ErrorCodes.ISSUED_AT_INVALID_FUTURE);

        jwtConsumer = new JwtConsumerBuilder()
                .setRequireIssuedAt()
                .setIssuedAtRestrictions(0,60)
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .build();

        iat = NumericDate.now().getValue();
        jwt = iatTestingJwt(iat);
        claims = jwtConsumer.processToClaims(jwt);
        assertThat(iat, equalTo(claims.getIssuedAt().getValue()));
    }

    private String dateTestingJwt(Long nbf, Long iat, Long exp) throws JoseException
    {
        JwtClaims claims = new JwtClaims();
        if (nbf != null) { claims.setNotBefore(NumericDate.fromSeconds(nbf)); }
        if (iat != null) { claims.setIssuedAt(NumericDate.fromSeconds(iat)); }
        if (exp != null) { claims.setExpirationTime(NumericDate.fromSeconds(exp)); }
        claims.setJwtId("meh123");
        claims.setStringClaim("etc.", "etc., etc., etc...");
        String payload = claims.toJson();

        return signClaims(payload);
    }


    private String iatTestingJwt(long when) throws JoseException
    {
        return dateTestingJwt(null, when, null);
    }

    private String signClaims(String payload) throws JoseException
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setPayload(payload);
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        return jws.getCompactSerialization();
    }


    @Test
    public void requireIntegrityOption() throws JoseException, InvalidJwtException
    {
        EllipticCurveJsonWebKey jwkP256 = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        jwkP256.setKeyId("ec2");

        EllipticCurveJsonWebKey jwkP384 = EcJwkGenerator.generateJwk(EllipticCurves.P384);
        jwkP384.setKeyId("ec3");

        EllipticCurveJsonWebKey jwkP512 = EcJwkGenerator.generateJwk(EllipticCurves.P521);
        jwkP512.setKeyId("ec5");

        RsaJsonWebKey jwkRSA = RsaJwkGenerator.generateJwk(2048);
        jwkRSA.setKeyId("r2");

        RsaJsonWebKey jwkRSA_b = RsaJwkGenerator.generateJwk(2048);
        jwkRSA_b.setKeyId("r2-b");

        OctetSequenceJsonWebKey jwkOct128 = OctJwkGenerator.generateJwk(128);
        jwkOct128.setKeyId("128bits");
        OctetSequenceJsonWebKey jwkOct256 = OctJwkGenerator.generateJwk(256);
        jwkOct256.setKeyId("256bits");
        OctetSequenceJsonWebKey jwkOct512 = OctJwkGenerator.generateJwk(512);
        jwkOct256.setKeyId("512bits");

        // mixing verification and decryption keys like this without a 'use' indicator isn't wise but is just to simplify this test
        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jwkOct512, jwkP512, jwkOct256, jwkP256, jwkRSA, jwkP384, jwkOct128, jwkRSA_b);
        VerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jsonWebKeySet.getJsonWebKeys());
        DecryptionKeyResolver decryptionKeyResolver = new JwksDecryptionKeyResolver(jsonWebKeySet.getJsonWebKeys());

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setExpectedAudience("a")
                .setExpectedIssuer("i")
                .setExpectedSubject("s")
                .setRequireExpirationTime()
                .setDisableRequireSignature()
                .setEnableRequireIntegrity()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setJwsAlgorithmConstraints(AlgorithmConstraints.DISALLOW_NONE)
                .setDecryptionKeyResolver(decryptionKeyResolver)
                .setJweAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLOCK,
                        KeyManagementAlgorithmIdentifiers.RSA1_5,
                        KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW,
                        KeyManagementAlgorithmIdentifiers.PBES2_HS384_A192KW,
                        KeyManagementAlgorithmIdentifiers.PBES2_HS512_A256KW))
                .build();


        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setAudience("a");
        jwtClaims.setIssuer("i");
        jwtClaims.setExpirationTimeMinutesInTheFuture(10);
        jwtClaims.setSubject("s");
        String claimsJson = jwtClaims.toJson();


        // signed and encrypted is okay
        JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(claimsJson);
        jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jsonWebSignature.setKey(jwkRSA.getRsaPrivateKey());
        jsonWebSignature.setKeyIdHeaderValue(jwkRSA.getKeyId());
        String jws = jsonWebSignature.getCompactSerialization();
        JsonWebEncryption jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(jws);
        jsonWebEncryption.setContentTypeHeaderValue("JWT");
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jsonWebEncryption.setKey(jwkP256.getECPublicKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkP256.getKeyId());
        String jwe = jsonWebEncryption.getCompactSerialization();
        JwtContext jwtCtx = jwtConsumer.process(jwe);
        assertThat(jwtCtx.getJwtClaims().getClaimsMap().size(), equalTo(4));

        // signed only is okay too
        jwtCtx = jwtConsumer.process(jws);
        assertThat(jwtCtx.getJwtClaims().getClaimsMap().size(), equalTo(4));

        // signed only is okay
        jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(claimsJson);
        jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384);
        jsonWebSignature.setKey(jwkP384.getPrivateKey());
        jsonWebSignature.setKeyIdHeaderValue(jwkP384.getKeyId());
        jws = jsonWebSignature.getCompactSerialization();
        jwtCtx = jwtConsumer.process(jws);
        assertThat(jwtCtx.getJwtClaims().getClaimsMap().size(), equalTo(4));

        // HMACed only is okay
        jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(claimsJson);
        jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jsonWebSignature.setKey(jwkOct256.getKey());
        jsonWebSignature.setKeyIdHeaderValue(jwkOct256.getKeyId());
        jws = jsonWebSignature.getCompactSerialization();
        jwtCtx = jwtConsumer.process(jws);
        assertThat(jwtCtx.getJwtClaims().getClaimsMap().size(), equalTo(4));

        // HMACed and encrypted is okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(jws);
        jsonWebEncryption.setContentTypeHeaderValue("JWT");
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        jsonWebEncryption.setKey(jwkP256.getECPublicKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkP256.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        jwtCtx = jwtConsumer.process(jwe);
        assertThat(jwtCtx.getJwtClaims().getClaimsMap().size(), equalTo(4));

        // HMACed only is okay
        jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(claimsJson);
        jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA512);
        jsonWebSignature.setKey(jwkOct512.getKey());
        jsonWebSignature.setKeyIdHeaderValue(jwkOct512.getKeyId());
        jws = jsonWebSignature.getCompactSerialization();
        jwtCtx = jwtConsumer.process(jws);
        assertThat(jwtCtx.getJwtClaims().getClaimsMap().size(), equalTo(4));

        // asymmetric encryption only is NOT okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(claimsJson);
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jsonWebEncryption.setKey(jwkP256.getECPublicKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkP256.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        InvalidJwtException invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwe, jwtConsumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.INTEGRITY_MISSING));

        // asymmetric encryption only is NOT okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(claimsJson);
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jsonWebEncryption.setKey(jwkP256.getECPublicKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkP256.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwe, jwtConsumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.INTEGRITY_MISSING));

        // asymmetric encryption only is NOT okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(claimsJson);
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        jsonWebEncryption.setKey(jwkP256.getECPublicKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkP256.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwe, jwtConsumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.INTEGRITY_MISSING));


        // asymmetric encryption only is NOT okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(claimsJson);
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A192KW);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384);
        jsonWebEncryption.setKey(jwkP256.getECPublicKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkP256.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwe, jwtConsumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.INTEGRITY_MISSING));

        // symmetric encryption only is okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(claimsJson);
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jsonWebEncryption.setKey(jwkOct128.getKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkOct128.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        jwtCtx = jwtConsumer.process(jwe);
        assertThat(jwtCtx.getJwtClaims().getClaimsMap().size(), equalTo(4));

        // symmetric encryption only is okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(claimsJson);
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jsonWebEncryption.setKey(jwkOct256.getKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkOct256.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        jwtCtx = jwtConsumer.process(jwe);
        assertThat(jwtCtx.getJwtClaims().getClaimsMap().size(), equalTo(4));

        // symmetric encryption only is okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(claimsJson);
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A256KW);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        jsonWebEncryption.setKey(jwkOct256.getKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkOct256.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        jwtCtx = jwtConsumer.process(jwe);
        assertThat(jwtCtx.getJwtClaims().getClaimsMap().size(), equalTo(4));


        // asymmetric encryption only is NOT okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(claimsJson);
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jsonWebEncryption.setKey(jwkRSA_b.getRsaPublicKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkRSA_b.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwe, jwtConsumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.INTEGRITY_MISSING));

        // asymmetric encryption only is NOT okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(claimsJson);
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384);
        jsonWebEncryption.setKey(jwkRSA_b.getRsaPublicKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkRSA_b.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwe, jwtConsumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.INTEGRITY_MISSING));

        // asymmetric encryption only is NOT okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(claimsJson);
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        jsonWebEncryption.setKey(jwkRSA_b.getRsaPublicKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkRSA_b.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwe, jwtConsumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.INTEGRITY_MISSING));

        // signed with public key as hmac key attack must not work
        jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(claimsJson);
        jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jsonWebSignature.setKey(new HmacKey(jwkRSA.getRsaPublicKey().getEncoded()));
        jsonWebSignature.setKeyIdHeaderValue(jwkRSA.getKeyId());
        jws = jsonWebSignature.getCompactSerialization();
        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jws, jwtConsumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.MISCELLANEOUS));


        // asymmetric encryption only is NOT okay
        jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setPlaintext(claimsJson);
        jsonWebEncryption.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, RSA1_5));
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA1_5);
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jsonWebEncryption.setKey(jwkRSA_b.getRsaPublicKey());
        jsonWebEncryption.setKeyIdHeaderValue(jwkRSA_b.getKeyId());
        jwe = jsonWebEncryption.getCompactSerialization();
        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwe, jwtConsumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.MISCELLANEOUS));  // b/c  RSA1_5 was blocked
        jwtConsumer.setJweAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);   // allow RSA1_5
        invalidJwtException = SimpleJwtConsumerTestHelp.expectProcessingFailure(jwe, jwtConsumer);
        assertTrue(invalidJwtException.hasErrorCode(ErrorCodes.INTEGRITY_MISSING));  // now fail w/ no integrity
    }




    @Test
    public void someBasicAudChecks() throws InvalidJwtException
    {
        JwtClaims jwtClaims = JwtClaims.parse("{\"aud\":\"example.com\"}");

        JwtConsumer jwtConsumer = new JwtConsumerBuilder().build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.com").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);


        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org", "example.com", "k8HiI26Y7").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org", "nope", "nada").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"sub\":\"subject\"}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience(false, "example.org", "www.example.org").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience(true, "example.org", "www.example.org").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"aud\":[\"example.com\", \"usa.org\", \"ca.ca\"]}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org", "some.other.junk").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("usa.org").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("ca.ca").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("ca.ca", "some.other.thing").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("noway", "ca.ca", "some.other.thing").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("usa.org", "ca.ca", "random").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("usa.org", "ca.ca").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("usa.org", "ca.ca", "example.com").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"aud\":[\"example.com\", 47, false]}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"aud\":20475}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"aud\":{\"aud\":\"example.org\"}}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);
    }

    @Test
    public void someBasicIssChecks() throws InvalidJwtException
    {
        JwtClaims jwtClaims = JwtClaims.parse("{\"iss\":\"issuer.example.com\"}");
        JwtConsumer jwtConsumer = new JwtConsumerBuilder().build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer(null).build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer(false, null).build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("issuer.example.com").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer(false, "issuer.example.com").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("nope.example.com").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"sub\":\"subject\"}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("issuer.example.com").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer(false, "issuer.example.com").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer(false, null).build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"iss\":[\"issuer1\", \"other.one\", \"meh\"]}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("issuer.example.com").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"iss\":[\"issuer1\", \"nope.not\"]}");
        jwtConsumer = new JwtConsumerBuilder().build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"iss\":\"accounts.google.com\"}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuers(true, "https://accounts.google.com", "accounts.google.com").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);
        jwtClaims = JwtClaims.parse("{\"iss\":\"https://accounts.google.com\"}");
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuers(true, "https://fake.google.com", "nope.google.com").build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"iss\":\"d\"}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuers(true, "a", "b", "c", "d", "e").build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);
        jwtClaims = JwtClaims.parse("{\"iss\":\"x\"}");
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);


        JwtClaims withIss = JwtClaims.parse("{\"iss\":\"x\"}");
        JwtClaims noIss = JwtClaims.parse("{\"notiss\":\"meh\"}");

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer(true, null).build();
        SimpleJwtConsumerTestHelp.goodValidate(withIss, jwtConsumer);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(noIss, jwtConsumer, ErrorCodes.ISSUER_MISSING);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer(null).build();
        SimpleJwtConsumerTestHelp.goodValidate(withIss, jwtConsumer);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(noIss, jwtConsumer, ErrorCodes.ISSUER_MISSING);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuers(true).build();
        SimpleJwtConsumerTestHelp.goodValidate(withIss, jwtConsumer);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(noIss, jwtConsumer, ErrorCodes.ISSUER_MISSING);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuers(true, null).build();
        SimpleJwtConsumerTestHelp.goodValidate(withIss, jwtConsumer);
        SimpleJwtConsumerTestHelp.expectValidationFailureWithErrorCode(noIss, jwtConsumer, ErrorCodes.ISSUER_MISSING);
    }

    @Test
    public void someBasicSubChecks() throws InvalidJwtException
    {
        JwtClaims jwtClaims = JwtClaims.parse("{\"sub\":\"brian.d.campbell\"}");
        JwtConsumer jwtConsumer = new JwtConsumerBuilder().build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setRequireSubject().build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"name\":\"brian.d.campbell\"}");
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"sub\":724729}");
        jwtConsumer = new JwtConsumerBuilder().setRequireSubject().build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"sub\":{\"values\":[\"one\", \"2\"]}}");
        jwtConsumer = new JwtConsumerBuilder().build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);
    }

    @Test
    public void someBasicJtiChecks() throws InvalidJwtException
    {
        JwtClaims jwtClaims = JwtClaims.parse("{\"jti\":\"1Y5iLSQfNgcSGt0A4is29\"}");
        JwtConsumer jwtConsumer = new JwtConsumerBuilder().build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setRequireJwtId().build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"notjti\":\"lbZ_mLS6w3xBSlvW6ULmkV-uLCk\"}");
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().build();
        SimpleJwtConsumerTestHelp.goodValidate(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"jti\":55581529751992}");
        jwtConsumer = new JwtConsumerBuilder().setRequireJwtId().build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);

        jwtClaims = JwtClaims.parse("{\"jti\":[\"S0w3XbslvW6ULmk0\", \"5iLSQfNgcSGt7A4is\"]}");
        jwtConsumer = new JwtConsumerBuilder().build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jwtClaims, jwtConsumer);
    }

    @Test
    public void someBasicTimeChecks() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims jcs = JwtClaims.parse("{\"sub\":\"brian.d.campbell\"}");
        JwtConsumer consumer = new JwtConsumerBuilder().build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireIssuedAt().build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireNotBefore().build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);


        jcs = JwtClaims.parse("{\"sub\":\"brian.d.campbell\", \"exp\":1430602000}");
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602000)).build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602000)).setAllowedClockSkewInSeconds(10).build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430601000)).build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430601000)).setAllowedClockSkewInSeconds(6000).build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430602002)).build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602002)).setAllowedClockSkewInSeconds(1).build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602002)).setAllowedClockSkewInSeconds(2).build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602002)).setAllowedClockSkewInSeconds(3).build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430602065)).build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602065)).setAllowedClockSkewInSeconds(60).build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602065)).setAllowedClockSkewInSeconds(120).build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);


        jcs = JwtClaims.parse("{\"sub\":\"brian.d.campbell\", \"nbf\":1430602000}");
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430602000)).build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430601999)).build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430601983)).setAllowedClockSkewInSeconds(30).build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430601983)).setAllowedClockSkewInSeconds(3000).build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);

        jcs = JwtClaims.parse("{\"sub\":\"brian.d.campbell\", \"nbf\":1430602000, \"iat\":1430602060, \"exp\":1430602600 }");
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setRequireNotBefore().setRequireIssuedAt().setEvaluationTime(NumericDate.fromSeconds(1430602002)).build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);

        jcs = JwtClaims.parse("{\"sub\":\"brian.d.campbell\", \"nbf\":1430603000, \"iat\":1430602060, \"exp\":1430602600 }");
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602002)).build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);


        jcs = JwtClaims.parse("{\"sub\":\"brian.d.campbell\", \"nbf\":1430602000, \"iat\":1430602660, \"exp\":1430602600 }");
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602002)).build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);


        jcs = JwtClaims.parse("{\"sub\":\"brian.d.campbell\", \"exp\":1430607201}");
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430600000)).build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430600000)).setMaxFutureValidityInMinutes(90).build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430600000)).setMaxFutureValidityInMinutes(120).build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430600000)).setMaxFutureValidityInMinutes(120).setAllowedClockSkewInSeconds(20).build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);
    }

    @Test
    public void someBasicChecks() throws InvalidJwtException
    {
        JwtClaims jcs = JwtClaims.parse("{\"sub\":\"subject\", \"iss\":\"issuer\", \"aud\":\"audience\"}");
        JwtConsumer consumer = new JwtConsumerBuilder().setExpectedAudience("audience").setExpectedIssuer("issuer").build();
        SimpleJwtConsumerTestHelp.goodValidate(jcs, consumer);

        consumer = new JwtConsumerBuilder()
                .setExpectedAudience("nope")
                .setExpectedIssuer("no way")
                .setRequireSubject()
                .setRequireJwtId()
                .build();
        SimpleJwtConsumerTestHelp.expectValidationFailure(jcs, consumer);
    }

    @Test
    public void testNpeWithNonExtractableKeyDataHS256() throws Exception
    {
        byte[] raw = Base64Url.decode("hup76LcA9B7pqrEtqyb4EBg6XCcr9r0iOCFF1FeZiJM");
        FakeHsmNonExtractableSecretKeySpec key = new FakeHsmNonExtractableSecretKeySpec(raw, "HmacSHA256");
        JwtClaims claims = new JwtClaims();
        claims.setExpirationTimeMinutesInTheFuture(5);
        claims.setSubject("subject");
        claims.setIssuer("issuer");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setKey(key);
        String jwt = jws.getCompactSerialization();
        JwtConsumerBuilder jwtConsumerBuilder = new JwtConsumerBuilder();
        jwtConsumerBuilder.setAllowedClockSkewInSeconds(60);
        jwtConsumerBuilder.setRequireSubject();
        jwtConsumerBuilder.setExpectedIssuer("issuer");
        jwtConsumerBuilder.setVerificationKey(key);
        JwtConsumer jwtConsumer = jwtConsumerBuilder.build();
        JwtClaims processedClaims = jwtConsumer.processToClaims(jwt);
        System.out.println(processedClaims);
    }

    @Test
    public void testNpeWithNonExtractableKeyDataAxxxKW() throws Exception
    {
        littleJweRoundTrip(KeyManagementAlgorithmIdentifiers.A128KW, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256, "mmp7iLc1cB7cQrEtqyb9c1");
        littleJweRoundTrip(KeyManagementAlgorithmIdentifiers.A192KW, ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384, "X--mSrs-JGaf0ulQQFSoJGH0vjrfe_c1");
        littleJweRoundTrip(KeyManagementAlgorithmIdentifiers.A256KW, ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512, "j-DJVQ9ftUV-muUT_-yjP6dB9kuypGeT6lEGpCKOi-c");
    }

    // @Test direct doesn't currently work w/ non extractable keys and will require some deeper changes to treat the CEK as a key rather than bytes
    public void testNpeWithNonExtractableKeyDataDirect() throws Exception
    {
        littleJweRoundTrip(KeyManagementAlgorithmIdentifiers.DIRECT, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256, "j-DJVQ9ftUV-muUT_-yjP6dB9kuypGeT6lEGpCKOi-c");
        littleJweRoundTrip(KeyManagementAlgorithmIdentifiers.DIRECT, ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384, "X--mSrs-JGaf0ulQQFSoJGH0vjrfe_c1X--mSrs-JGaf0ulQQFSoJGH0vjrfe_c1");
        littleJweRoundTrip(KeyManagementAlgorithmIdentifiers.DIRECT, ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512, "j-DJVQ9ftUV-muUT_-yjP6dB9kuypGeT6lEGpCKOi-cj-DJVQ9ftUV-muUT_-yjP6dB9kuypGeT6lEGpCKOi-c");

        JceProviderTestSupport jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setEncryptionAlgsNeeded(AES_128_GCM, AES_192_GCM, AES_256_GCM);

        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(
            new JceProviderTestSupport.RunnableTest()
            {
                @Override
                public void runTest() throws Exception
                {
                    littleJweRoundTrip(KeyManagementAlgorithmIdentifiers.DIRECT, AES_128_GCM, "mmp7iLc1cB7cQrEtqyb9c1");
                    littleJweRoundTrip(KeyManagementAlgorithmIdentifiers.DIRECT, AES_192_GCM, "X--mSrs-JGaf0ulQQFSoJGH0vjrfe_c1");
                    littleJweRoundTrip(KeyManagementAlgorithmIdentifiers.DIRECT, AES_256_GCM, "j-DJVQ9ftUV-muUT_-yjP6dB9kuypGeT6lEGpCKOi-c");
                }
            }
        );
    }

    private void littleJweRoundTrip(String alg, String enc, String b64uKey) throws Exception
    {
        byte[] raw = Base64Url.decode(b64uKey);
        Key key = new FakeHsmNonExtractableSecretKeySpec(raw, "AES");
        JwtClaims claims = new JwtClaims();
        claims.setExpirationTimeMinutesInTheFuture(5);
        claims.setSubject("subject");
        claims.setIssuer("issuer");
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(claims.toJson());
        jwe.setAlgorithmHeaderValue(alg);
        jwe.setEncryptionMethodHeaderParameter(enc);
        jwe.setKey(key);

        String jwt = jwe.getCompactSerialization();
        JwtConsumerBuilder jwtConsumerBuilder = new JwtConsumerBuilder();
        jwtConsumerBuilder.setAllowedClockSkewInSeconds(60);
        jwtConsumerBuilder.setRequireSubject();
        jwtConsumerBuilder.setExpectedIssuer("issuer");
        jwtConsumerBuilder.setDecryptionKey(key);
        jwtConsumerBuilder.setDisableRequireSignature();
        JwtConsumer jwtConsumer = jwtConsumerBuilder.build();
        JwtClaims processedClaims = jwtConsumer.processToClaims(jwt);
        assertThat(processedClaims.getSubject(), equalTo("subject"));
    }

    @Test
    public void testNpeWithNonExtractableKeyDataAxxxGCMKW() throws Exception
    {
        JceProviderTestSupport jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setKeyManagementAlgsNeeded(A128GCMKW, A192GCMKW, A256GCMKW);
        jceProviderTestSupport.setEncryptionAlgsNeeded(AES_128_GCM, AES_192_GCM, AES_256_GCM);

        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(
            new JceProviderTestSupport.RunnableTest()
            {
                @Override
                public void runTest() throws Exception
                {
                    littleJweRoundTrip(A128GCMKW, AES_128_GCM, "mmp7iLc1cB7cQrEtqyb9c1");
                    littleJweRoundTrip(A192GCMKW, AES_192_GCM, "X--mSrs-JGaf0ulQQFSoJGH0vjrfe_c1");
                    littleJweRoundTrip(A256GCMKW, AES_256_GCM, "j-DJVQ9ftUV-muUT2-yjP6dB9kuypGeT6lEGpCKOi-c");
                }
            }
        );
    }


    @Test
    public void customizationCallbacksWithCritHeaders() throws Exception
    {
        JwtClaims claims = new JwtClaims();
        claims.setSubject("me");
        claims.setAudience("a");
        claims.setIssuer("i");
        claims.setExpirationTimeMinutesInTheFuture(10);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setCriticalHeaderNames("fake.meh");

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(jws.getCompactSerialization());
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        jwe.setContentTypeHeaderValue("jwt");
        jwe.setCriticalHeaderNames("fake.blah");

        System.out.println(claims);
        String nestedJwt = jwe.getCompactSerialization();

        System.out.println(nestedJwt);

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKey(ExampleRsaKeyFromJws.PRIVATE_KEY)
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setExpectedAudience("a")
                .setRequireExpirationTime()
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(nestedJwt, consumer);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(ExampleRsaKeyFromJws.PRIVATE_KEY)
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setExpectedAudience("a")
                .setRequireExpirationTime()
                .setJwsCustomizer(new JwsCustomizer()
                {
                    @Override
                    public void customize(JsonWebSignature jws, List<JsonWebStructure> nestingContext)
                    {
                        jws.setKnownCriticalHeaders("fake.meh");
                    }
                })
                .setJweCustomizer(new JweCustomizer()
                {
                    @Override
                    public void customize(JsonWebEncryption jwe, List<JsonWebStructure> nestingContext)
                    {
                        jwe.setKnownCriticalHeaders("fake.blah");
                    }
                })
                .build();

        JwtContext ctx = consumer.process(nestedJwt);
        assertThat(ctx.getJoseObjects().size(), equalTo(2));
        assertThat(ctx.getJwtClaims().getSubject(), equalTo("me"));
        assertThat(ctx.getJwt(), equalTo(nestedJwt));
    }


    @Test
    public void iatBeforeNbfShouldBeOkay() throws Exception
    {
        JwtClaims claims = new JwtClaims();
        claims.setSubject("me");
        claims.setNotBeforeMinutesInThePast(1);
        claims.setExpirationTimeMinutesInTheFuture(10);
        NumericDate issuedAt = NumericDate.now();
        issuedAt.addSeconds(-120);
        claims.setIssuedAt(issuedAt);
        claims.setAudience("audience");
        claims.setIssuer("issuer");

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        String jwt = jws.getCompactSerialization();


        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setExpectedAudience("audience")
                .setExpectedIssuer("issuer")
                .setVerificationKey(ExampleEcKeysFromJws.PUBLIC_256)
                .setRequireExpirationTime()
                .setRequireNotBefore()
                .setRequireIssuedAt()
                .build();

        JwtContext ctx = jwtConsumer.process(jwt);
        assertThat(ctx.getJwtClaims().getSubject(), equalTo("me"));
    }

    @Test
    public void constraintsWereHittingInKeySelectionBeforeJwtConsumerSetThemToBeOkay() throws Exception
    {
        // a test for https://bitbucket.org/b_c/jose4j/issues/84/algorithm-constraint-issue-with

        JwtClaims claims = new JwtClaims();
        claims.setSubject("me");
        claims.setExpirationTimeMinutesInTheFuture(5);
        claims.setAudience("the audience");
        claims.setIssuer("the issuer");

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);
        String jwt = jws.getCompactSerialization();

        final JwksVerificationKeyResolver jwksVerificationKeyResolver = new JwksVerificationKeyResolver(Collections.<JsonWebKey>emptyList());

        VerificationKeyResolver resolver = new VerificationKeyResolver()
        {
            @Override
            public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext)
            {
                try
                {
                    return jwksVerificationKeyResolver.resolveKey(jws, nestingContext);
                }
                catch (UnresolvableKeyException e)
                {
                    return null;
                }
            }
        };

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setExpectedAudience("the audience")
                .setExpectedIssuer("the issuer")
                .setRequireExpirationTime()
                .setVerificationKeyResolver(resolver)
                .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .setDisableRequireSignature()
                .build();

        // this should not fail (it was previously) with a algorithm constraints message
        // NO_CONSTRAINTS is set but the key selection was calling jws.getAlgorithm() before the
        // constraints were set on the jws so the jws still had the default constraints

        JwtContext ctx = jwtConsumer.process(jwt);
        assertThat(ctx.getJwtClaims().getSubject(), equalTo("me"));

    }

    @Test
    public void databrokerAtAndIdToken() throws Exception
    {
        // just testing some content produced by a different system as a compatibility check in
        // the unit tests

        String jwtAt = "eyJraWQiOiJBY2Nlc3MgVG9rZW4gU2lnbmluZyBLZXkgUGFpciIsImFsZyI6IlJTNTEyIn0." +
                "eyJzdWIiOiJVc2Vyc1wvNTgzZjQ0Y2ItNjk4MC00NTk5LWJjZGMtYzdlMzRmZGE5YTRiIiwic2NvcG" +
                "UiOiJ1cm46cGluZ2lkZW50aXR5OnNjb3BlOm1hbmFnZV90b3RwIHVybjpwaW5naWRlbnRpdHk6c2Nv" +
                "cGU6bWFuYWdlX2V4dGVybmFsX2lkZW50aXRpZXMgdXJuOnBpbmdpZGVudGl0eTpzY29wZTpjaGFuZ2" +
                "VfcGFzc3dvcmQgdXJuOnBpbmdpZGVudGl0eTpzY29wZTp2YWxpZGF0ZV9waG9uZV9udW1iZXIgdXJu" +
                "OnBpbmdpZGVudGl0eTpzY29wZTp2YWxpZGF0ZV9lbWFpbF9hZGRyZXNzIHVybjpwaW5naWRlbnRpdH" +
                "k6c2NvcGU6cGFzc3dvcmRfcXVhbGl0eV9yZXF1aXJlbWVudHMgdXJuOnBpbmdpZGVudGl0eTpzY29w" +
                "ZTptYW5hZ2VfY29uc2VudHMgdXJuOnBpbmdpZGVudGl0eTpzY29wZTptYW5hZ2VfcHJvZmlsZSB1cm" +
                "46cGluZ2lkZW50aXR5OnNjb3BlOm1hbmFnZV9zZXNzaW9ucyIsImV4cCI6MTQ4NjEwMjc4NywiaWF0" +
                "IjoxNDg2MDU5NTg3LCJjbGllbnRfaWQiOiJAbXktYWNjb3VudEAiLCJqdGkiOiJhLm1KNThpdyJ9." +
                "J5LjQyKbLzPGgjtoFI6vNzguy5DhLAQiEtLj035cHDo9_sZbqVwc2z-kCt5jTOtcOVaBOO8nErdyBk" +
                "k2S7-_t_nWQWims2EBTpvs5NXdP8M__1Y7PB0YUHaUNIf4EdgO0oxcxh0QWN6Wz2UbFgMN2Qav-7eT" +
                "--RVTe37VZST0H1k8xbECRJUFbb949RkfZXE2Of7xy_LJEGjBNNEOwkm9YOo3Cuf1fG8la-xovD3fR" +
                "Hduc9VZ4CDpXuwwaBYxAnSNcmR4e9cw1ke_Uu6Op0OAJ9tJcb-i4k3F3WI1Yb6VteoYTC0URpBpyfs" +
                "A4bI0lZi_S8Bdx_7patIJE-DRamPDg";

        // encoding of n is using base64 rather than base64url but jose4j can accept either even
        // though it's not per spec
        String jwksJson = "{\"keys\":[" +
                "{\"kty\":\"RSA\",\"use\":\"sig\"," +
                 "\"kid\":\"Access Token Signing Key Pair\"," +
                 "\"n\":\"AIKoYDcZLHB1GKacf7mGfzz8LUmT4rHzEOlQLM1FBsxLNZ40BAONAcTUlf3JyOQujrR4on" +
                  "h/cIh6O+38FDw953irZMURzvD0GvWjiX/KTuaJ6zOr9zbamTDF0nQPB5Q9VwOTGdyDnKTNR9b/Vsu" +
                  "+dAaDBOi32wZ4gZWFVXOCD1EGy2gX99gwBCOCkK0GQI4VmifNI3omeG727l5jpnsfpzkZuluQBHl3" +
                  "+CV/TPPvyGP/4i5wUAhpZv+s6rnKIgp0bNrE6jQ2EzO9sTk10jr/L4mJ7kSN7OLyXiXWz5K1J3REa" +
                  "u+Fl371zOe2erLHzWrXxFh3s6iKcyZElnTXO3Ljwxs=\"," +
                 "\"e\":\"AQAB\"," +
                 "\"x5c\":[\"MIIDIzCCAgugAwIBAgIERXO5bzANBgkqhkiG9w0BAQsFADBCMR8wHQYDVQQKExZQaW5" +
                  "nIElkZW50aXR5IEtleSBQYWlyMR8wHQYDVQQDExZEYXRhIEdvdmVybmFuY2UgQnJva2VyMB4XDTE3" +
                  "MDIwMTIzMDY1NVoXDTM3MDEyNzIzMDY1NVowQjEfMB0GA1UEChMWUGluZyBJZGVudGl0eSBLZXkgU" +
                  "GFpcjEfMB0GA1UEAxMWRGF0YSBHb3Zlcm5hbmNlIEJyb2tlcjCCASIwDQYJKoZIhvcNAQEBBQADgg" +
                  "EPADCCAQoCggEBAIKoYDcZLHB1GKacf7mGfzz8LUmT4rHzEOlQLM1FBsxLNZ40BAONAcTUlf3JyOQ" +
                  "ujrR4onh/cIh6O+38FDw953irZMURzvD0GvWjiX/KTuaJ6zOr9zbamTDF0nQPB5Q9VwOTGdyDnKTN" +
                  "R9b/Vsu+dAaDBOi32wZ4gZWFVXOCD1EGy2gX99gwBCOCkK0GQI4VmifNI3omeG727l5jpnsfpzkZu" +
                  "luQBHl3+CV/TPPvyGP/4i5wUAhpZv+s6rnKIgp0bNrE6jQ2EzO9sTk10jr/L4mJ7kSN7OLyXiXWz5" +
                  "K1J3REau+Fl371zOe2erLHzWrXxFh3s6iKcyZElnTXO3LjwxsCAwEAAaMhMB8wHQYDVR0OBBYEFCc" +
                  "K/2ZcyzmDUW5CluqLc1KLKyeSMA0GCSqGSIb3DQEBCwUAA4IBAQBlRYvmBzzNjMNeb/zjcT2ysn1v" +
                  "ji8AZdPhdD1oMiSmV2yVF8ln09ckYUglghf3j041NXC676/NtcKBEztVFFQ3jOExDnwFD9YHkOE49" +
                  "FeTNWssq2UTwZVfw/+Vt7cFp1BVpUihwIs5vxaxA2LmLwswYgjUgU2G/G8k6oy/kvM2AT4JzXdsy8" +
                  "uwQCe68wI8F2k4wMfiz7i7df9jDWtfMzxOH9q5Gp3xMZWm/PUzzRjDVe1qJ+RvBC0YS7u/UgYXHKc" +
                  "tzJBZsJXq8ePVJC1U3z6/72VDj0m7IUEy8BIljhWOde9yHIwJrquBRY9xzDxGNGargPKXdRqjkzCO" +
                  "T4puYyhV\"]}]}";

        JsonWebKeySet jwks = new JsonWebKeySet(jwksJson);

        JwksVerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setEvaluationTime(NumericDate.fromSeconds(1486059597))
                .build();

        JwtContext ctx = jwtConsumer.process(jwtAt);
        assertThat("Users/583f44cb-6980-4599-bcdc-c7e34fda9a4b", equalTo(ctx.getJwtClaims().getSubject()));

        String jwtIdToken = "eyJraWQiOiJBY2Nlc3MgVG9rZW4gU2lnbmluZyBLZXkgUGFpciIsImFsZyI6IlJTMjU2In0." +
                "eyJhdF9oYXNoIjoiRHV5TTVOMlRqaEwzSklMZkdBbklwZyIsImFjciI6IkRlZmF1bHQiLCJzdWIiOiJVc2V" +
                "yc1wvNTgzZjQ0Y2ItNjk4MC00NTk5LWJjZGMtYzdlMzRmZGE5YTRiIiwiYXVkIjoiQG15LWFjY291bnRAIi" +
                "wiYW1yIjpbInB3ZCJdLCJhdXRoX3RpbWUiOjE0ODY0MTM0ODMsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc" +
                "3QiLCJleHAiOjE0ODY0MTQ3NjMsImlhdCI6MTQ4NjQxMzg2Mywibm9uY2UiOiJhZGZzIn0." +
                "SKa7zfhXRc0bEhMilnJPtjitRmLdFux_2EM8shwC5PW44Yx6Ji0BVebeY0Q9lQ7NK5QV7JI5dUjlDT4rfLi" +
                "MDa64hUkJQF6AxQkT70xT1vuHs7e34oBuGDQKlDqe5mtKVM-6qX2aW8ILHCELQc_N7dND2KzLzqaH9pf2aX" +
                "SmPS5xo8VF4nAhy5L_G7wW9wqeI4FDt8pVuvG--iptP98TecIV85pKe5iRSRwqrSEWUCVdA1cuvmyXcAFg1" +
                "jpGNwZ2GHhmTPvld5_nGUhrFFZnBYhJLBkbhY0E02ongrlmwvEVUVN1Qvnx18dSBErQ5kOXyfcbdp-S_cIT" +
                "o0tXJmxJ7g";

        jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setRequireIssuedAt()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setExpectedAudience("@my-account@")
                .setExpectedIssuer("https://localhost")
                .setEvaluationTime(NumericDate.fromSeconds(1486413864))
                .build();

        ctx = jwtConsumer.process(jwtIdToken);
        assertThat("Users/583f44cb-6980-4599-bcdc-c7e34fda9a4b", equalTo(ctx.getJwtClaims().getSubject()));
    }

    @Test
    public void testSkipVerificationKeyResolutionOnNone() throws Exception
    {
        // https://bitbucket.org/b_c/jose4j/issues/95/

        JwtClaims claims = new JwtClaims();
        claims.setSubject("me");
        claims.setExpirationTimeMinutesInTheFuture(5);
        claims.setAudience("the audience");
        claims.setIssuer("the issuer");

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);
        String jwt = jws.getCompactSerialization();

        VerificationKeyResolver exceptionThrowingResolver = new VerificationKeyResolver()
        {
            @Override
            public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException
            {
                throw new UnresolvableKeyException("This VerificationKeyResolver always throws this exception.");
            }
        };

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setExpectedAudience("the audience")
                .setExpectedIssuer("the issuer")
                .setRequireExpirationTime()
                .setVerificationKeyResolver(exceptionThrowingResolver)
                .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .setDisableRequireSignature()
                .build();
        // should fail with exception from VerificationKeyResolver
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedAudience("the audience")
                .setExpectedIssuer("the issuer")
                .setRequireExpirationTime()
                .setVerificationKeyResolver(exceptionThrowingResolver)
                .setSkipVerificationKeyResolutionOnNone()
                .setDisableRequireSignature()
                .build();
        // should fail with AlgorithmConstraints on 'none'
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);


        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedAudience("the audience")
                .setExpectedIssuer("the issuer")
                .setRequireExpirationTime()
                .setVerificationKeyResolver(exceptionThrowingResolver)
                .setSkipVerificationKeyResolutionOnNone()
                .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .setDisableRequireSignature()
                .build();

        // should succeed b/c of setSkipVerificationKeyResolutionOnNone and AlgorithmConstraints.NO_CONSTRAINTS
        JwtContext ctx = jwtConsumer.process(jwt);
        assertThat(ctx.getJwtClaims().getSubject(), equalTo("me"));
    }
}
