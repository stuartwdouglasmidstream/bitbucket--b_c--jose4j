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

import org.hamcrest.CoreMatchers;
import org.jose4j.jwa.JceProviderTestSupport;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.OctJwkGenerator;
import org.jose4j.jwk.OctetKeyPairJsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.OkpJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.XDHKeyUtil;
import org.jose4j.keys.resolvers.JwksDecryptionKeyResolver;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

/**
 *
 */
public class JwksDecryptionKeyResolverUsingJwtConsumerTest
{
	private static final Logger log = LoggerFactory.getLogger(JwksDecryptionKeyResolverUsingJwtConsumerTest.class);

	@Test
    public void testResolveOkpKey() throws Exception
    {
        // skip this tests if XDH isn't available (before java 11 I think)
        org.junit.Assume.assumeTrue(new XDHKeyUtil().isAvailable());

        JwtClaims claims = new JwtClaims();
        claims.setSubject("example with OKP encryption key");

        EllipticCurveJsonWebKey signingKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        signingKey.setKeyId(UUID.randomUUID().toString());

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKey(signingKey.getPrivateKey());
        jws.setKeyIdHeaderValue(signingKey.getKeyId());
        jws.setPayload(claims.toJson());
        String signed = jws.getCompactSerialization();

        OctetKeyPairJsonWebKey encryptionKey =
                OkpJwkGenerator.generateJwk(OctetKeyPairJsonWebKey.SUBTYPE_X25519);
        encryptionKey.setKeyId(UUID.randomUUID().toString());

        List<JsonWebKey> dhKeys = new ArrayList<>();
        dhKeys.add(encryptionKey);
        dhKeys.add(OkpJwkGenerator.generateJwk(OctetKeyPairJsonWebKey.SUBTYPE_X25519));
        encryptionKey =
                OkpJwkGenerator.generateJwk(OctetKeyPairJsonWebKey.SUBTYPE_X25519);
        encryptionKey.setKeyId(UUID.randomUUID().toString());
        dhKeys.add(encryptionKey);

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
        jwe.setEncryptionMethodHeaderParameter(
                ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(encryptionKey.getPublicKey());
        jwe.setKeyIdHeaderValue(encryptionKey.getKeyId());
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setPayload(signed);
        String encrypted = jwe.getCompactSerialization();

        JwtConsumer consumer =
                new JwtConsumerBuilder()
                        .setDecryptionKeyResolver(new JwksDecryptionKeyResolver(dhKeys))
                        .setVerificationKeyResolver(new JwksVerificationKeyResolver(Arrays.asList(new JsonWebKey[]{signingKey})))
                        .build();

        assertThat(consumer.processToClaims(encrypted).getSubject(), CoreMatchers.equalTo("example with OKP encryption key"));
    }

    @Test
    public void testSymmetricKeysWithDir() throws JoseException, InvalidJwtException, MalformedClaimException
    {
        String json = "{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"one\",\"k\":\"SGfpdt9Jq5H5eR_JbwmAojgUlHIH0GoKz7COzLY1nRE\"}," +
                "{\"kty\":\"oct\",\"kid\":\"deux\",\"k\":\"Fvlp7BLzRr-a9pOKK7BA25om7u6cY2o9Lz6--UAFWXw\"}," +
                "{\"kty\":\"oct\",\"kid\":\"tres\",\"k\":\"izcqzDJd6-7rP5pnldgK-jcDjT6xXdo3bIjwgeWAYEc\"}]}";
        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(json);

        String jwt = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiZGV1eCJ9" +
                "." +
                ".JruwzL7TaQ1Fub8Hw6yYmQ" +
                ".b4B9F3kerVHvyGB5zb40lkTqxulLbMhwFi-qvPfFwwbuyPVPf5s7TeT3i3MLRs0-l_1hP5bPxIEEnOEOBbqTGwO1TWuBn_lQsR8XpQRp6t4H0eaXZsnBqOa3MeEtmGpo" +
                ".Hzbvc--4g2nqIaYoYkc2pQ";

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1424015558))
                .setRequireExpirationTime()
                .setExpectedIssuer("from")
                .setExpectedAudience("to")
                .setDecryptionKeyResolver(new JwksDecryptionKeyResolver(jsonWebKeySet.getJsonWebKeys()))
                .setDisableRequireSignature()
                .build();

        JwtContext jwtCtx = jwtConsumer.process(jwt);
        assertThat(jwtCtx.getJoseObjects().size(), CoreMatchers.equalTo(1));
        assertThat(jwtCtx.getJwtClaims().getSubject(), CoreMatchers.equalTo("Scott Tomilson, not Tomlinson"));

        String badJwt = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiZGV1eCJ9" +
                "." +
                ".JruwzL7TaQ1Fub8Hw6yYmQ" +
                ".b4B9F3kerVHvyGB5zb40lkTqxulLbMhwFi-qvPfFwwbuyPVPf5s7TeT3i3MLRs0-l_1hP5bPxIEEnOEOBbqTGwO1TWuBn_lQsR8XpQRp6t4H0eaXZsnBqOa3MeEtmGpo" +
                ".Hzbvc__4g2nqIaYoYkc___";  // bad tag

        try
        {
            JwtClaims claims = jwtConsumer.processToClaims(badJwt);
            fail("shouldn't have processed/validated but got " + claims);
        }
        catch (InvalidJwtException e)
        {
        	log.debug("this was expected and is okay: {}", e.toString());
        }

        json = "{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"one\",\"k\":\"SGfpdt9Jq5H5eR_JbwmAojgUlHIH0GoKz7COzLY1nRE\"}," +
                "{\"kty\":\"oct\",\"kid\":\"two\",\"k\":\"izcqzDJd6-7rP5pnldgK-jcDjT6xXdo3bIjwgeWAYEc\"}]}";
        jsonWebKeySet = new JsonWebKeySet(json);
        jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1424015558))
                .setRequireExpirationTime()
                .setExpectedIssuer("from")
                .setExpectedAudience("to")
                .setDecryptionKeyResolver(new JwksDecryptionKeyResolver(jsonWebKeySet.getJsonWebKeys()))
                .setDisableRequireSignature()
                .build();

        try
        {
            JwtClaims claims = jwtConsumer.processToClaims(jwt);
            fail("shouldn't have processed/validated but got " + claims);
        }
        catch (InvalidJwtException e)
        {
            log.debug("this was expected and is okay: {}", e.toString());
        }
    }

    @Test
    public void testSymmetricKeysWithAesWrap() throws Exception
    {
        String json = "{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"1one\",\"k\":\"_-cqzgJ-_aeZkppR2JCOlx\"}," +
                "{\"kty\":\"oct\",\"kid\":\"deux\",\"k\":\"mF2rZpj_Fbeal5FRz0c0Lw\"}," +
                "{\"kty\":\"oct\",\"kid\":\"tres\",\"k\":\"ad2-dGiApcezx9310j4o7W\"}]}";
        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(json);

        String jwt = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiZGV1eCJ9" +
                ".UHa0kaUhz8QDHE_CVfpeC-ebzXapjJrQ5Lk4r8XvK1J5WD32UeZ3_A" +
                ".3pPAmmVX_elO_9lgfJJXiA" +
                ".8pNNdQ_BsTwFicdrCevByA4i7KAzb__qF6z6olEQ3M8HayMAwOJoeF0yhnkM0JcydcCiULRE_i8USvpXWiktBhIJ79nDlqHxK09JB6YGnkpBMZgAmWf1NJFmTlF4vRs6" +
                ".3_UixCVYQsUablSjTX8v2A";

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1424026062))
                .setRequireExpirationTime()
                .setExpectedIssuer("from")
                .setExpectedAudience("to")
                .setDecryptionKeyResolver(new JwksDecryptionKeyResolver(jsonWebKeySet.getJsonWebKeys()))
                .setDisableRequireSignature()
                .build();

        JwtContext jwtCtx = jwtConsumer.process(jwt);
        assertThat(jwtCtx.getJoseObjects().size(), CoreMatchers.equalTo(1));
        assertThat(jwtCtx.getJwtClaims().getSubject(), CoreMatchers.equalTo("Scott Tomilson, not Tomlinson"));
    }

    @Test
    public void testAsymmetricDecryptionKeys() throws Exception
    {
        String octKeysJson = "{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"uno\",  \"k\":\"aSqzs8KJZgnYb9c7d0zgdACK0-i0Hi3K-jcDjt8V0aF9aWY8081d1i2c33pzq5H5eR_JbwmAojgUl727gGoKz7\"}," +
                "{\"kty\":\"oct\",\"kid\":\"two\", \"k\":\"-v_lp7B__xRr-90pNCo7u6cY2o9Lz6-P--_0TWhAI4vMQFh6WeZu0fM4lui0Hi3K-jcDjt8V0aF9aWY0081dc1c\"}," +
                "{\"kty\":\"oct\",\"kid\":\"trois\",\"k\":\"_pMndrQmbXEK0-i0Hi3K-jcdDjt89Lz6-c_1_01ji-41ccx6-7rPpCK0-i0HiV0aFcc9d8bcKic10_aWY8081d\"}]}";

        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(octKeysJson);
        JwksVerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jsonWebKeySet.getJsonWebKeys());

        String decryptionKeysJson = "{\"keys\":[" +
                "{\"kty\":\"EC\",\"kid\":\"001\",\"x\":\"B8j3GQhgSvxDitJ7GtDQ_b5lFRIUl98T7TYuYLNQg4k\",\"y\":\"3P0i0nFQMng4OT3BrylKCtO4yQaXm6s-oGUYBf1u6hs\",\"crv\":\"P-256\",\"d\":\"vd2hw-2_RiBcQiUYomQIr6OwxRiLhiRG3yUjWUIaphI\"}," +
                "{\"kty\":\"EC\",\"kid\":\"003\",\"x\":\"q-EZUCCzI3Kvr6D_ZbH_W2PZa-GzamxAQeOTXEyiviA\",\"y\":\"PkdfdW-XCwO7y1vM69Y-vw3L8RfM6EfLs_49uzd605I\",\"crv\":\"P-256\",\"d\":\"UhUxGGxCj4V6oZg-za85XJ0sHa9xgExMVxAXEh5eVOw\"}," +
                "{\"kty\":\"EC\",\"kid\":\"003\",\"x\":\"q-EZUCCzI3Kvr6D_ZbH_W2PZa-GzamxAQeOTXEyiviA\",\"y\":\"PkdfdW-XCwO7y1vM69Y-vw3L8RfM6EfLs_49uzd605I\",\"crv\":\"P-256\",\"d\":\"UhUxGGxCj4V6oZg-za85XJ0sHa9xgExMVxAXEh5eVOw\"}]}";
        jsonWebKeySet = new JsonWebKeySet(decryptionKeysJson);
        JwksDecryptionKeyResolver decryptionKeyResolver = new JwksDecryptionKeyResolver(jsonWebKeySet.getJsonWebKeys());

        String jwt = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImtpZCI6IjAwMyIsImN0eSI6Imp3dCIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJqUGRiMlU4a0FJSTRRMXBjSnVHZS0yNlcyQ0NVNlNFTnhJX0JRWWh0X3M4IiwieSI6IlVSUjg5MmZDVGtUSFZ2cUFuYXpWa01QMFNQNFVyUUYtODFLVm9OV3p2WEkiLCJjcnYiOiJQLTI1NiJ9fQ" +
                "..YSs9jK_K7W9KPkXT379C-A" +
                ".NyWNDnO9y8xELimQpBYX55apvVDP0tUdqQqMOnYMZQVZ4rRKWfyoS9830IVZhE79hfMltPX0mK_5vj_NByH8rQV2gRHx4hv_off96Jq3dnlyUofwN5bleUKZLs14BgopG15lAkmOtsRfoxN56ZXTL9FWitcKYYTXbLcw5UPIM6nTePRJoh2ZAZpqBA7FJKX3aNBm9851zjDPFyTCLSMmCyFuqzeZGrF_Ic-KHSjVnwgslPW5Kca_XunQilEs9VWlinoSpf0HxqQRogGQIi8EmA" +
                ".flt8CcaCXWa23Ci5EhLdNw";

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1424266660))
                .setExpectedAudience("TO")
                .setExpectedIssuer("FROM")
                .setRequireExpirationTime()
                .setRequireSubject()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setDecryptionKeyResolver(decryptionKeyResolver)
                .build();

        JwtClaims claims = jwtConsumer.processToClaims(jwt);
        assertThat("ABOUT", equalTo(claims.getSubject()));
    }

    @Test
    public void asymmetricDecryptionKeysWithDisambiguate() throws Exception
    {
//        RsaJsonWebKey rsaJsonWebKey1 = RsaJwkGenerator.generateJwk(2048);
//        rsaJsonWebKey1.setUse(Use.ENCRYPTION);
//        rsaJsonWebKey1.setKeyId("r1");
//        RsaJsonWebKey rsaJsonWebKey2 = RsaJwkGenerator.generateJwk(2048);
//        rsaJsonWebKey2.setUse(Use.ENCRYPTION);
//        rsaJsonWebKey2.setKeyId("r2");
//        EllipticCurveJsonWebKey ellipticCurveJsonWebKey1 = EcJwkGenerator.generateJwk(EllipticCurves.P256);
//        ellipticCurveJsonWebKey1.setUse(Use.ENCRYPTION);
//        ellipticCurveJsonWebKey1.setKeyId("e1");
//        EllipticCurveJsonWebKey ellipticCurveJsonWebKey2 = EcJwkGenerator.generateJwk(EllipticCurves.P256);
//        ellipticCurveJsonWebKey2.setUse(Use.ENCRYPTION);
//        ellipticCurveJsonWebKey2.setKeyId("e2");
//        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(rsaJsonWebKey1, rsaJsonWebKey2, ellipticCurveJsonWebKey1, ellipticCurveJsonWebKey2);
//        System.out.println(jsonWebKeySet.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));

//        RsaJsonWebKey rsaJsonWebKey3 = RsaJwkGenerator.generateJwk(4096);
//        rsaJsonWebKey3.setUse(Use.ENCRYPTION);
//        rsaJsonWebKey3.setKeyId("r3");
//
//        RsaJsonWebKey rsaJsonWebKey4 = RsaJwkGenerator.generateJwk(3072);
//        rsaJsonWebKey4.setUse(Use.ENCRYPTION);
//        rsaJsonWebKey4.setKeyId("r4");

//        System.out.println(rsaJsonWebKey3.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
//        System.out.println(rsaJsonWebKey4.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));


        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet("{\"keys\":[" +
                "{\"kty\":\"RSA\",\"kid\":\"r1\",\"use\":\"enc\",\"n\":\"lFZ04QwtWu_hHgqlry40DuIhVZyl6ci6FzyLfkeHLH8xfCDLR-rvslxX-Ub3teVnPjZYdUFlZztuDo5kOFsF7TvUQMJhx00VZ6qugm-4LDSJ93ioGuo37vNDjMYBs0dEw_xV38e_m_Jo-oTJZN8xfZFroiR0cRNzac2e98lPa-TCxtOCuVp8Q8ro1Y6nC_1g51iY3nZXHfELX4vUxSh-4z7I0VkzCREQNYx-iKWw6MqEl2qG2mohiwlRexphf-1--8RuJ7FgubewzFv6dP_vCO9cYGi2qB0Gw6b9u8Jb60JYM7xLT3wGTQNfepiXQWESbVorxYiwZODP7d0tteD-eQ\",\"e\":\"AQAB\",\"d\":\"CTA3yi7ialUciStYqvq-L8PTE8YBwvLzj_fonhhZJ6jzTECNxvUnBtHQgzjhpCtDE2fzX8P-v3-_Z_hq_dCpk9HWanJ_8wPz1PmOGLdJ3bcdaq5XH1-tukfoQcKMHWpHOKqbOSLa3BKObSInhW-L1b7Zv2_ppI1zYzTg6XFXUZQAUzB9anvdQDiQRLTeLhCW3zZND-WtjrycvsgoIFApCwfWQMsv4Uhi7tedgwRt7_EBJcSO9vyGlE6Mf0tJCzCuwWWsfKbxc7NutR6y9Wh2_rGDgyzAxxT2v8E_CjmsuhYwz_a4PD5LcrpMYBq1_pTar-_ql-qMwDrsn682UUoRAQ\",\"p\":\"yTmQMaGX1Ja2z8wllKMc2QAdk04pBBRyQyNb3U2_B5hCpz1azvEC1jtgAFJaV9jW5K9b5M4sjdaA8HvWFcPMLtAU0T-e3INNpoW-mRTw71gZDbL_eW9bJBjBTUw2fltUQXNG1MrIw5aVsmEwkO3OJUyIIA0fVloLPVTczYG_pEE\",\"q\":\"vLdued0wjqKXJCZxHpW6ij_CNZKm1_ohApsJ6iF41KTjJAd-1lUlUzgY_As6Ck5a6hz8E_94mUv3ykn6NVFiLQIyGGyiCfU3J6jO4QmS7jZu75FtJuh-7J4Yj8V8eztupaPz69DgjvwQlxjFMUjk_AYjhRf5DzOf0lCd33ZqbDk\",\"dp\":\"f1tudusmlIebRuOXeX7POEzJaz0R2qIyO2n6r5OQb3cf4IeFnOqPeBX2Sd3VjjoQsIaIa8VOD6uOyiYmtnnJFmvecR2KJ1j3YYjOvEazw1iH6tK6vRoMnkkItyqgZtLY_d-_GdkKvjfloRPAUEoiqhrJITgM-HNfH79BTNRs_cE\",\"dq\":\"r_9iSMTAREXeLxiq5ps9HTHZLZ1XfJUJtCRjWrdcuPQN4cwbvkgqRzJKGsVdm773it79OKlJD66JqV7UumTr6o3hqmWluSO4DISia71CCmc5jrNR2Ld7p7DJt0u2jDchOdlt4r8qri7mSgQP46bX5zLSbY2t-T9sDfihQ4ZsOgE\",\"qi\":\"tvxPXVg0igyHL6Rqr7qUilqyG7oCZU3ycXxjuXqWMkhw1ISz7RlyBouOLjYGEaxDFVyVtLj8RIUr4Hks-q7nZnD80yik-JZdN-BsQYU2xaGGDUVJPYt7TiHeRadx_68DxQKqlMl7N0c6RVfcXWdTlRSWIPYNgYqjavRzC15pF-E\"}," +
                "{\"kty\":\"RSA\",\"kid\":\"r2\",\"use\":\"enc\",\"n\":\"yzFYB2Nqp5Wb34XQUBGRR33tp1jPVds46D3xwmTXPqjsbr4LMQqPWghtN_qE2bHldPJ9RJUk-i3UxnTAwR1bKLaCj6Aip_blZ4z_wK6IUIkJZk2nPD75YyhTpE9CqoI26lL2KBjMj3gn3cIxHi22BdGshppUbaf-ogH18LQ1bStM63uiflX44ud7GT4JVGaBczoad_cr-R1hs4kWZNdJrzBh7aPxebYnbAVd2CTeyXGYr_GIiq_sgtaBBISGoggruY5r-fva3R4YnhoTnmNeFOLDb99bzDPHbWhyjJ5nqBx7yaw1mT9uBnWno-h423bAT81TvXOJ2ogZ-jsYigx6xw\",\"e\":\"AQAB\",\"d\":\"Bf22Ib74Vb6fMkT-HQ5CNqsWMcP4QQjOBxL504h-TDZWL6G3hMJR8w6ijG783HUBVfm8YHmhSyXEy0vapGxa1BAljgSOYQjHlM5fJW2VTq1BCLIrcdGi2sianBKg3ZQp-Fi_3J4hPJhcseOC5-fjIQ1178tnHTXsgmxaYGF_3cXGkTiEg2xyph-eALczZlOA9_NitCySSO2R8tHAxpSqLujUb1tWvvAffGPu1pW2eJSDb9E2URRVX33yiGGbMNgFoMduBUUYiUKOBeq_zsGhuSnLqnfDbkIlhWiKfj-FRXPR72L9gJpZsiX_Tk_YZbxr3CphguL1_isvvCDgcPrmEQ\",\"p\":\"-KnLj5-Pyvgj-nUmpNEcY6TVrewK-GafZ53Cdo9-ko0cjt5CeW-y04JjUY3vTJRmFUNzqwj5LaYTDx7MJELCv9MiYB-x2LuAwKcfS8Pua1uyNusu6JraS_uRbR2JQVZ36DvNEBo57geRUZFCAYt2-d1WIXexQqXoXTNQ0P662E8\",\"q\":\"0TAZvdMIUpVG_x4Uo65nOTbJHLfTf7pBiYMGZuj74GQ6ggAWP9_EvW7azvhlCVu7W_0TjXLgxVU8WpTBUTjpU_J4ZMnB7jY5xImq7il9lZJCaZiubpjfzehb9UyMDMwtSnwhAT_6urUj0sk8KloA43ipDXN9tmKdoWZXxFE_IAk\",\"dp\":\"v7cpmrIKyxJFqvRntusCWFDd7hnu21VD0T9wjrhTfeoN-pih576WwTvmFxq3RPOlQP-gTl28v9UrHJ1CBzLxs7O07SeClvb5bY9sMZ3-VAd-f5kTsYKyi6KJnPcIu7dO-14f3CpcP4jWIW081rQQJtTfcy41HI2NeU33IStEI0E\",\"dq\":\"a7bK6nXJ6Uw4fJEuq4HYYRuWvxTg8PolWPuAxmjdmZPClMIastU0Zx63yK8ax5DWju1nrgQjPTlAlJvYV0xoyPMnjy5cj56YbF0_CNeQdP4U-G7IEubhBxPIlizOSKCyCZKVJCGfp5gyVA2Oz3f80SSGWAjKCKoK5NrgApSbXpE\",\"qi\":\"b3MC0KYMSuw2-FlUbVwUV6CTWfeEoz0iFQnfKNgiPpzz99NAfLeUaQQ2tjYGFUwLA5vMi4Rf1YF6gxPAYfLpkn2oKvlOqEn7go1pkbHMiQrC6kOG6Ubgek2h47sa0KUEkT91eKZa29fb4qcMHW4TJuR-IGYzJ532zpEReSk2oek\"}," +
                "{\"kty\":\"RSA\",\"kid\":\"r3\",\"use\":\"enc\",\"n\":\"pkTznDIyNrI9wvfoFqv3yZpHv5PBeSXxdvOIKtsrKTSXxgDqjfn3jS4CiZidUjW1TzwwkYRZYU3Ei-M7qecudUs1QFdoBUNyd7V_X-ueToD1K-JvQCCrb74bzQWHVfsb2bRfuLw3Tyw3JwnWU3Q-P7OP08INyitwFw9Oz5DvKovtuOyAh3-CT8eSXcPMy2LQTt7WW8h2YeMq1EvndAc67ohiz-q3u2Qqwbbyv-p237mL_90JLE4xMBnLNey4FDjtXbXIq8T8QbvGyn4Dc67ZxH4-izAxi_siA_3z0H7oTYRaeNL4JuNqhoB0R4CgThfofdGVGZVWPyyowzSI-7nxbMHYNNse96wDnbTTKC8pP-qDjExRYjzm4iNueaMzzcq3wAIpR5z2tZp1oULOo43R0kcXC51sKrenJWnqIaIj_WsENRAWWHsrh5IycgySWyytaGVgQHaeBagYJHzRcrhWk10e81M8oMtdPPL1MLS0bbU3CTpDcacr4KyAKAL8sVi7-M2UVqvtWkEZCJ9q1cgOFwcp0t8ZKOpw9OgVeyo-P8HoDpfeXM_WecqNuHSRBlJGbAIfKErBiAUAKFmdEKyHtuUi-Ni6cEwDgjrSxX3apxG_41POrZjZBuuV6FYBcR1wqnTr8k-_z49Kv8ZGF3yszgcV3IQ4qK3-M_qqypnEai8\",\"e\":\"AQAB\",\"d\":\"BA_s3b-SNNOPqRBH0NSnFftZeRJB6KpR0cSrFSpL-H1ASgZNX2ZLMzKmaDiHe3Hez06apyt9yDVPXIA9kxiYAiXyE_OEEeuEbpf2F-Ct-kqx8r5dASBAiqyGibCdY683Y88W2ZtrmdkW3d131DZ5AN3BC_zn5le_rNM4azTQyxAmdjKnrz0hG2mLp2kjEJhbm4Rb5gZ_R0P2u2oWqmHfgY1pJfLyReHxc3sl8iS8fm8jlFQ7pvlKwAXuo494Ldz4MPvB09nZCegYYsEdEiSkTbssia0F64lusCdHtNaCPsaW3psqPz-mI3QcTdTpgGRFegbL_EHcR2iEFQTXEJi0j8KqfWCsyKY57lJV0Pn6rMTBJ5sF0qSJTnCUZV1BDUN1phhDQoCD0Y44PKdIzsmsgmn1FGjCfixWAMtFSQz8jigyZmsGnmDjKPFUXygL_IYAUqejeObUUe07EYEw4b9a-XgwWe5k1OldLEwOQMji8r7Q38zq6l0plJLdKRJzbF5q7b24TcFrASklca93VkD4hSnLaneeQ_BMVndeJ2f4zPjgFyn70jKXCqralMY1v07I1eSrScRq7it259E2vPas2Y09LeNZxv4ifF6HoD-9eGoUia8NjzKzLj2x3YA39oxRNUidKH3Fk8MCLgAiV2DqVCogFg0EBLEnj7ZjpVjRVCU\",\"p\":\"6xgjjtpZ_ZRkpm45BFaXhN1f6w6-YC_EZkndORGWmYzOitcoJQ64JdEFN-NO_tdmtoNXgV-Fqy_x3jxrXLuHsBv6krxgCfg0Qh9b55K34zikX7AeKSFSrvKcoIXXQVTEQ82gO4TL8T04uWCsoTqN2FNrSENXx6b3MgTaMTWA0JHG7mbfJybcm-3C-qiNKa698dgEpLTgqzDYjn3BoDYD1Ct9Zuy4_nZb8_V_LZxETxwDr7TMA9PKM3I7xqcrH62HVRJoYlrJ7giD9MF0Dw9c0cNcfbcj-gjRonDHekFd8cZUyOM2kCs43uStAWxBf58kUOOptb5czb8vayE9lmCF8w\",\"q\":\"tQ4HyQEsWV0YWBrpZBBHpvlIJQW5hbGM-4zq0DuN5n1T6kYJOjF4zLEnblHUp5skbASaQsHABDQVNDWrCSsYUV_9SvSldjQ7Yp_CbpNOOx4p9D2LYLe1XQVvut8Hloxt4-sqoS0A-alv7FJgWLHrTjozrsnGj7g5N0Q8AFTgB4SHu2jrt-xROg6ZkfFBFOHYPzJERRfm8qYS9sP3-u4aI3KI6y8POG9za1OPWsBkqXmMS4Lwe5QjtTCPeec9Lh_ipQaaxSSf5-jz01NOLTTywkyPNzV5wB13yl39KhKBZFs6wpZERfpnAOH7ROqKq0Q5RIg9qY9rzGFOs4HP4IHt1Q\",\"dp\":\"3rJqFItQjb6BLYrh5fMk6s5Nazv3KOR21jKIJeQ8Vc4lZS31ME1mMSR0HgHsNcnT2XZHcR0MYSI0qsFvLlPScAfA8DkTfL4quqw8AfxgxxRD2QTbPTj8uw7FQeYnBxMGK_hgHaFpE2dcEXa7cKsn7NDwom5we4b1SOOB0PWOxYQh_nliUBMnDWpHtevudJq8AZkQpPlWjbPin_AOd_ZS4CwmSVZa02lJJ6rZQ1pw9sNh1pKcY8-_DcbbSw3V8tcNiI-8Y9b-y8YzQanzh8SUt3upZMkUgmjSNF9DBtNe64VlkTpy2FSpNbNHEz76OKuG2j0e6TOfc6L0hzXgwk9C8w\",\"dq\":\"of7RvGlOUw7Wz04U8TEXyzBT-rwqiJKaQCCPoI0Io-gTAxRzARxup0cCrtSM3wITDor3sy9ELP6k0jgKtoNWmMi4Cy7mNOL7F302LFWks4SDqUK_yGPW5EoO9DbFxVAUqs8pL1ji_H8740i5Z-KZVT8CKyvie4kruGVXAjzuzgsonuh7r-7DppyVj107DAIeyDyjlOaT_xvU7_HbmSsdPAYot7U9exNNRARZyatG5dQZUR7xKMEdSesPFNVviiuBUIKeTDI-2PM35ictVYmAg5SYt58jNl-nZOu_rrssBq0R4DUvFSW8r6-CcOEh_adnTghQk7v9ibqu_jHx20ClmQ\",\"qi\":\"mnQbqLs7dXj9qKHWBMWWfthizpy4YMgpJKwuI1Z5dAbbMIqa--3L3Lx4umCSs6kUPaIVH4_MvehAgcxC1IVilkQe5tpXsC84QAye-XFThsgASNGB7NW1tvnGEoNnUMTd_Ifk4Dr6yCS89tf3eZynDQw1xnk-W2XOXcNTOX2mQYr8v6R2wSL8Vy-CApzQr6vu4pthQBte5aCpYf85YLsNTQrSdxCdj7K3IE0CZKxMdWfgOugGU0dTZJO3U1IPAHgqN5XwNSI1-C6igTqGY7i6SdfG-raBSxrjsLDLWNWS3EpDrWxQQBUP8am4IrSmaKJB-k6Gn0Sde8DMYRTL3uwdAA\"}," +
                "{\"kty\":\"RSA\",\"kid\":\"r4\",\"use\":\"enc\",\"n\":\"srRMqzPSg5CoMyaY5YErUQBRJkn0QhkzSiIIPA6dow3MnhR2_1S-D4aNHdet29Yc6qs9Qh6HIirMWcp2FPaKfaIZaJ-Q_-9gVyPDWlKHp9jSTeSetDCxm401e8XxNMjluGqb-3uQWE9W0Ka7IlDXXW1KhLYZ75xDaP5Y1c2n84uMRMKwylNCKQv0KlHIRDhsPfHx82khTGUb1XMqom7FWO8Ii4whRr7Glw0JiXj8ANHGozVTP-EVkZqFRJmwLG-ndyvsJOclEwwrXYqklFloU7WUwZQ5M08F-g-6XlSNHtaDcFagUUQKXG8zSb6GqXtEfhrs0mwI1D66b3txAf_76w9phkwlHp0Ab_lLuJLAr0j_ACtXbyxUQvHOV8QXmBuSwl7dVqAXFXGBQNGRtdewjPYgzmS4l_SzjgvC8jRTd-xzSof_gIIbSrKEtMnIoKhMCexyYGXkEzfv7aZH92_ZDGa9Cszlyqd3TJrDjj75zrkztc3coMOgbIVHoet_Ptmx\",\"e\":\"AQAB\",\"d\":\"H4aKLfuu7BHVcmyhNX-zjg8hwcDzK8P5Vd8qF7o2WgEBs3OFyKaA_wksFPMrEyizIj0CSgtLqJ3nPgHnEeyqYt55YAkiUdw_YTAIcwMzNkucUix-SOh8NKZVJJg3ZKn6SK3aBaP3Q3T_qkB3q-aaD7vLlRzw92HYTInuTw2ATwkzvh-gg5jrh4U51ktmKo7PnZ_0oI3P14PQxLeT8mLbQsSse73FUw8txpEAuTVUM6rOQZWTMaY6IV0inIcGWth5ZYWsRnG_0tSyWwdV4L9SoAcGpKbDaZz4aVe9_BauwaBZC02-jeF9-tQXoIp4JehQKJIVwNQDXlwaSNoCEtibCa6ElEHAkTuKeFa9EZQ0_raRZbpxLIayOwGej0xtqrk2Xx1sPHbHCBvoBbU3aA87RiqHfe2GKqQ112HYs2Bli0lYUVD383HW6z52-oD1P_rBSldDi-HD_ALnanV9WIlsDXy35n-O2UrYH8acbgei_acpbqCew_ut_xwL23-O8Chp\",\"p\":\"yYrW8ZH3FxxBoDD9eI3mi02L6MwXNyyptYWHubefzgiAXxjjc9_ZyWFeNPuuhFibWABqU9ZRBOo4rz8tVMt3BCD4uy3Tc-CgqHE_rF3IRCCtpKg4zjDk8zR38z1MgdkFOmptMua4sRyu3zNHUjQaE0TM7oMbmTEZum5_sTXh35nYr93zS6PXEaXat1SQQJCmeY1_O9Oh33mRcqNUQRNNy9m5UrBXPEzzpBvpbpbpJyCFGOXwl620JyMMhz12AAOd\",\"q\":\"4v2yuCdZkdz_z4k3gj5fr9BYCQ3soqi-EGQVWjBBWbnQdRjlVqR2GDptoOu0O5Pfp7KtNY2ZM2R6u5cPp_bpC8lKdXEivIC08STAUxQs_2OGN00_zIc25iruGoErfelWu3lLy5MeIxQyNhplgfLwYEFfM4vU0Aj-56YpgiKG0IL4yJTUTHoKrDnc6EewkOTsaBeyplSM8Bb-8Fiz9rDCw-qAoYyfiurOtRbgqePwE6Mb-qrBf18xWV3H7eMzmWQl\",\"dp\":\"KznD7_vGawZ8bMcVFg4ZLDdtknhzYjoKDAyfl41ykNXx8nN8FRYlt7NSaTqxq2D1sGIma-TDa7JwheWe61jYJeKMdljVyTycOIRRi75xfWsk0vPhexexgxf1wg2box3QqT66PPiPFC16tBRjb5YNIaTX7y_fc3O8eOfKK0_LKhHtD4si604winBwAHH6nl5n1hoq98HkLfH86AFvyKVDQj1oKfv4Oc6nUsNJxZZIW0P2R-jJOT7gLKSvwzHDZS1h\",\"dq\":\"B0GS5_4iB96nssuxIZG631Tqq4dtbBm20bFRWWu3exXMiyG7mxRwzf94J6_BODJW8PZuQQsAvbrVjY-bqYPkGUNbBPwT3zDCF_9TwpQfiB53WOc4ReKAp8TxjZlZeZHu-tk6ygwu53Iq1L3tRsUsV_dfArfSmr_e3iraotVVt-6n40mWq8cu9ih3XlmEVG1s_TrctCJ5yucBSU-cmSM3ZqnlaMSlCPzOlM1hayzlLMuHBnFU9Cxn2HJ-BKXBrYKd\",\"qi\":\"vp98xF5g3Qrl7N8xrMxcv3dlzc604uriOJWlU1i0cnitx4A41sy_0gGUU7CUK-E-3zsM0jyKbhdmxAS7RKjKJx4bRLd-sSrhyX7CVuQfnhf4FPhrvDWhrpP_gF00sZp0YlzJCK2RTAYVJu-l0h-Ha-aeqM-i38sB5Mil2G3pEfesTnU8P0QkpDiKyIPenSVyndBgCyEwM7ohg0R4J6v7pr91CKe5VU5pBVCUQ-Cc9qKz_5eQYrZn9KdI4uuJQgG6\"}," +
                "{\"kty\":\"EC\",\"kid\":\"e1\",\"use\":\"enc\",\"x\":\"zw4_6TARtwAsHFDw4Q1gr65t6BMl6lXOmmOMA3R0q58\",\"y\":\"O0Gb45b83A8FRe-DH_xJ4H0dsaQVskZMT_RBIKaSGOc\",\"crv\":\"P-256\",\"d\":\"wS8p82eHEJ6909QDq2duIcVNCtUt15BSkGGepzDnJQ8\"}," +
                "{\"kty\":\"EC\",\"kid\":\"e2\",\"use\":\"enc\",\"x\":\"A47oP1eLgWo7NsiKGV2Q983D3oNxLnRDlgtEi7HCtSI\",\"y\":\"4CjFGXRHDmm3g_cSB2YZPYsnxorc4tAEJRD35wBu0ys\",\"crv\":\"P-256\",\"d\":\"FfbZoojxU87u-lLtCUMHRWwFU2w1eB6yEEuJmm-Rhno\"}" +
                "]}");

//        JsonWebKey k = jsonWebKeySet.findJsonWebKey("e2", null, null, null);
//
//        JsonWebEncryption jwe = new JsonWebEncryption();
//        jwe.setPayload("{\"iss\":\"e2\"}");
//        jwe.setKey(k.getKey());
//        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
//        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);
//        String compactSerialization = jwe.getCompactSerialization();
//
//        System.out.println(compactSerialization);

        List<JsonWebKey> jsonWebKeys = jsonWebKeySet.getJsonWebKeys();
        Collections.shuffle(jsonWebKeys);

        String jwer1 = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.KCBLPXZnT5aaFM6jnB7QhFhZ3dkD4Ky7OF8SWlHbKzWx4kuGtOvre0MJBnfMuwEND1a67QdNO1rag1_P78fEcz5Zs71aYDnwNWAagQhsWXx32-1gtmQR90etJkbT8qDA98MIB_WdBeJLwUD8CIOz1BrMcWHdX9NZcVxi1NZW4boi9qw_Dtst9r806FMnSR0-wmp2wTzYsR5Lmalg3WA-QwM-N2pMXi3J_C2QavM7ml1Lg1utjis_YrsvAI19iWPLRcYhH0dIaf2uRCAzhzHy8g4kQkbp70LNd9XXCNq-3lhA-1VqnsLi0V2LV3H0olR06jre9VOHC0fgzeUCTA6UrA.wvCoV_JQhm9eEsco.04sa9TFzOz0lfaWR.h8spUAPHrZ0EEQr5xIJTjg";
        String jwer2 = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.rFG7gYCkOAxjaRIFoz_DUy0f83G2UG2V9DSTRcg-4e05EPSiDLE9KCWsWZU43cwl2JwQP1zUTyU-K3MW6u7lpFXGIX-9AqFqPFTfGUYDymnM7JJ9Bjyl42dCaNuOx-0UhodIUbxMUFsSDQ1LvWIDuJKCQsK7mXw0Lrbj-Wa_xK8CpsD9Z25BulwkD5srfvJ0zRvhlX5SA3enGlYWp8hPxDcyXfP2IJK_JBFzefK76soDQ-IcpOTE6BbdATHYL5aQUKM1rKdShZL1M7VISI_lUFx1FC8BIKf_k8YTYGNIE41_sCnNXhrKzs4g45B_sYpNnX71Rs3g6WOXKtjW83Pf_Q.mVb0fTuF6u72mYGS.YwwtHaLPzxnU3krt.aEXq4r4JaJhZxvxRX16ZPw";
        String jwer3 = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.He_InN2BUqvy9sfq_uwOnXTrEdFcII-eJiwNIE9ZH806VWK8WvxBLYczgR4nfB6E603Wk7pgMM85ys2ONu-GfEhprkC2Kmogcs18V2k7rXx6Vs7qMYkC-KCesa-qxOkh2Q5p_JbXcXoMvhpRtcPxHnIPSc8A8thlV0nUPvCSFJF9oqNlb3LnYiPFSj7UN0NbrrRP1l_UJs51MGRsAsz6EvpXhZQe_lDZ2RvKzXdJjV32-1amYbZKINFnneyomRLv4koc5wHdrl_tra95W1GnnzccQ8JaHUDyXAp7wKWcG2m0gXcbvVvYaHtXYlKujrYrcX31LXla4gFIJ1dOvqHn7562fUWvyBiBe-umpgwXjQq8pt6flHlKedYfefwAjg96z1_vIGD995Z2vZ2DjQmsBFGa5P115IeO2czGRicmo3x9Oy_KnJ3y2Xl7Dd_ItNzKXuDTRxYqU3bghQ0G6toouddpMvdwYhUqZ4eRkgqiMrNa2tjA-Zss8FaBoxfBTWR3TMOMFoydPPnlyJrla8MunL5GAyALxAYKF2AOhEXX_isPtORjLyIiUaril0SpUYGpwsftb2enjJqxFJRHmfCFw7_0fmwD8TLfr00DW6r8Jgf4nZgeA90V6IzJZq_1hvj1eoTlNSBYbN6i3Ur9l7XCGBiQDgFzshBW7jm5NlUCrpU.A-j_xMjFn2cA4K9-.wpw6nZ7unz9AgSY3.6OjRwTShxXHmdby5aAUYAQ";
        String jwer4 = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.awMpGgt-UTQYOQBO4Z-sABTVhrSr70xjotF0FMXWFqUB4iyoihdLRBTnrpjTb6o-orOqA6EMsv6oDZZelSn3J5Ul-cJSPibXuehlX9VQkZv4NDhP38sUeuXNp0IDtNcJeX2tFI2t6W2uFrCYwIkvh8f8bKHR_yUZslFBWAXRwLX9H2PjyQLXhir3hM1SAOKrQQVjaoPOum1n-3F6p_fh8gZYaxVJiJ2Yq9kdqVwY1wjsEq5sq8JN3j8szfE1GBVYHQhdn2I96bpX9OI97ma-XDIZwmQRgHT1mMByhbTG1SzQiIOc4CXGp5b5zER8j55MVZYB0L3iPYVEELY5YjWULc8XTUeSkejvH3ENuckqBoMijx3vb3NIXUFvY1IW6l0DeCxEbv87ead-qSRoCNWKsZKtNX457jhtl9xXO0lrjT5kB_D9z_0SbT2X7CTIZ4vMGBbzsII-Ip_cWwl8xYXxwy9OGVsiRt1F0q1JgtNS35lNP9hZvDJksWPo59ebqXEw.ocPwwRIpGa8R3Vov.-XXqFCYM6zkOTl3j.hOTzs7STvZrH3Agtm4DoNg";
        String jwee1 = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiNGUxaFNtaG1wUkFTQWU0SGZvNnRWbFlUbmhIazhXU3RWN3JhdXowSERmdyIsInkiOiJqY2xlM1I3UW9heU1STEdkU3RVRnRXa19tbEFRcDdnUjRzMmlUSW9oUFk0IiwiY3J2IjoiUC0yNTYifX0.sYGf24IFPG3CpVZNAK6ApOKu6-xO7R7y.sK0Sh40MFYIRPF0j.iZRU7bUnWlMW7XT_.gDIU8HHyNxf7HORt6b8NfQ";
        String jwee2 = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJCM1FfY2xpV2FDMXlJVy0zZmZkY3hUNUx4eDlwMEtLWjIzOFF2aDRaM0JVIiwieSI6InVwdTRqMkJrMHE4a09JSEVGdGxLNF9ZZE9LRHBNbHNJNlBiUTZpM0dfOGciLCJjcnYiOiJQLTI1NiJ9fQ..UThHTj4NK_nuFTlN.3jZICW52F3hFd_jg.RJxLHhVO_-EJYYWrui3CWw";

        final ArrayList<String> jwes = new ArrayList<>(Arrays.asList(jwee1, jwee2, jwer1, jwer2, jwer3, jwer4));
        Collections.shuffle(jwes);

        final JwksDecryptionKeyResolver decryptionKeyResolver = new JwksDecryptionKeyResolver(jsonWebKeys);
        decryptionKeyResolver.setDisambiguateWithAttemptDecrypt(true);

        JceProviderTestSupport jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setEncryptionAlgsNeeded(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                for (String jwe : jwes)
                {
                    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                            .setSkipAllValidators()
                            .setDisableRequireSignature()
                            .setDecryptionKeyResolver(decryptionKeyResolver)
                            .build();

                    JwtClaims jwtClaims = jwtConsumer.processToClaims(jwe);
                    assertThat(jwtClaims.getIssuer(), is(notNullValue()));
                }

                String jwer4bad = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.Ac5pGgt-UTQYOQBO4Z-sABTVhrSr70xjotF0FMXWFqUB4iyoihdLRBTnrpjTb6o-orOqA6EMsv6oDZZelSn3J5Ul-cJSPibXuehlX9VQkZv4NDhP38sUeuXNp0IDtNcJeX2tFI2t6W2uFrCYwIkvh8f8bKHR_yUZslFBWAXRwLX9H2PjyQLXhir3hM1SAOKrQQVjaoPOum1n-3F6p_fh8gZYaxVJiJ2Yq9kdqVwY1wjsEq5sq8JN3j8szfE1GBVYHQhdn2I96bpX9OI97ma-XDIZwmQRgHT1mMByhbTG1SzQiIOc4CXGp5b5zER8j55MVZYB0L3iPYVEELY5YjWULc8XTUeSkejvH3ENuckqBoMijx3vb3N3XUFvY1IW6l0DecXEbv87ead-qSRoCNWKsZKtNX457jhtl9xXO0lrjT5kB_D9z_0SbT2X7ffsZ4vMGBbzsII-Ip_cWwl8xYXxwy9OGVsiRt1F0q1JgtNS35lNP9hZvDJksWPo77ebqXEw.ocPwwRIpGacR3VO1.-XXqFCYM6zkOTl3j.hOTzs7STvZrH3Agtm4DoNg";
                try
                {
                    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                            .setSkipAllValidators()
                            .setDisableRequireSignature()
                            .setDecryptionKeyResolver(decryptionKeyResolver)
                            .build();

                    JwtClaims claims = jwtConsumer.processToClaims(jwer4bad);
                    fail("shouldn't have processed/validated but got " + claims);
                }
                catch (InvalidJwtException e)
                {
                    log.debug("this was expected and is okay: {}", e.toString());
                }
            }
        });
    }

    @Test
    public void simpleSymmetricDecryptionKeysWithDisambiguate() throws Exception
    {
        List<JsonWebKey> keys = new ArrayList<>();
        OctetSequenceJsonWebKey jwk = OctJwkGenerator.generateJwk(256);
        jwk.setKeyId("1");
        keys.add(jwk);
        jwk = OctJwkGenerator.generateJwk(256);
        jwk.setKeyId("2");
        keys.add(jwk);
        jwk = OctJwkGenerator.generateJwk(256);
        jwk.setKeyId("3");
        keys.add(jwk);
        jwk = OctJwkGenerator.generateJwk(256);
        jwk.setKeyId("4");
        keys.add(jwk);
        jwk = OctJwkGenerator.generateJwk(256);
        jwk.setKeyId("5");
        keys.add(jwk);
        jwk = OctJwkGenerator.generateJwk(256);
        jwk.setKeyId("6");
        keys.add(jwk);

        List<String> jwes = new ArrayList<>();

        for (JsonWebKey jsonWebKey : keys)
        {
            String jwe = makeSimpleSymmetricJwe(jsonWebKey);
            jwes.add(jwe);
        }

        JwksDecryptionKeyResolver decryptionKeyResolver = new JwksDecryptionKeyResolver(keys);
        decryptionKeyResolver.setDisambiguateWithAttemptDecrypt(true);

        for (String jwe : jwes)
        {
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                    .setSkipAllValidators()
                    .setDisableRequireSignature()
                    .setDecryptionKeyResolver(decryptionKeyResolver)
                    .build();

            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwe);
            assertThat(jwtClaims.getIssuer(), is(notNullValue()));
        }

        jwk = OctJwkGenerator.generateJwk(256);
        jwk.setKeyId("nope");
        String jwe = makeSimpleSymmetricJwe(jwk);


        try
        {
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                    .setSkipAllValidators()
                    .setDisableRequireSignature()
                    .setDecryptionKeyResolver(decryptionKeyResolver)
                    .build();

            JwtClaims claims = jwtConsumer.processToClaims(jwe);
            fail("shouldn't have processed/validated but got " + claims);
        }
        catch (InvalidJwtException e)
        {
            log.debug("this was expected and is okay: {}", e.toString());
        }

    }

    private String makeSimpleSymmetricJwe(JsonWebKey jsonWebKey) throws JoseException
    {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setPayload("{\"iss\":\"made w/ kid "+ jsonWebKey.getKeyId()+"\"}");
        jwe.setKey(jsonWebKey.getKey());
        return jwe.getCompactSerialization();
    }

}
