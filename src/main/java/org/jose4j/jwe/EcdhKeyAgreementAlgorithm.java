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

package org.jose4j.jwe;

import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmAvailability;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.jwe.kdf.KdfUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.OkpJwkGenerator;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.jwx.KeyValidationSupport;
import org.jose4j.keys.EcKeyUtil;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.keys.XDHKeyUtil;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UncheckedJoseException;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.NamedParameterSpec;

/**
 */
public class EcdhKeyAgreementAlgorithm extends AlgorithmInfo implements KeyManagementAlgorithm
{
    String algorithmIdHeaderName = HeaderParameterNames.ENCRYPTION_METHOD;

    public EcdhKeyAgreementAlgorithm()
    {
        setAlgorithmIdentifier(KeyManagementAlgorithmIdentifiers.ECDH_ES);
        setJavaAlgorithm("ECDH"); // or XDH
        setKeyType(EllipticCurveJsonWebKey.KEY_TYPE); // or "OKP" but not quite ready to make changes at this layer for that
        setKeyPersuasion(KeyPersuasion.ASYMMETRIC);
    }

    public EcdhKeyAgreementAlgorithm(String algorithmIdHeaderName)
    {
        this();
        this.algorithmIdHeaderName = algorithmIdHeaderName;
    }

    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, byte[] cekOverride, ProviderContext providerContext) throws JoseException
    {
        KeyValidationSupport.cekNotAllowed(cekOverride, getAlgorithmIdentifier());
        String keyPairGeneratorProvider = providerContext.getGeneralProviderContext().getKeyPairGeneratorProvider();
        SecureRandom secureRandom = providerContext.getSecureRandom();

        PublicJsonWebKey ephemeralJwk;

        if (managementKey instanceof ECPublicKey)
        {
            ECPublicKey receiverKey = (ECPublicKey) managementKey;
            checkCurveAllowed(receiverKey);
            ephemeralJwk = EcJwkGenerator.generateJwk(receiverKey.getParams(), keyPairGeneratorProvider, secureRandom);
        }
        else if (XDHKeyUtil.isXECPublicKey(managementKey))
        {
            XECPublicKey receiverKey = (XECPublicKey) managementKey;
            NamedParameterSpec namedParameterSpec = (NamedParameterSpec) (receiverKey).getParams();
            String name = namedParameterSpec.getName();
            ephemeralJwk = OkpJwkGenerator.generateJwk(name, keyPairGeneratorProvider, secureRandom);
        }
        else
        {
            throw new InvalidKeyException("Inappropriate key for ECDH: " + managementKey);
        }

        return manageForEncrypt(managementKey, cekDesc, headers, ephemeralJwk, providerContext);
    }

    private void checkCurveAllowed(ECKey receiverKey) throws InvalidKeyException
    {
        ECParameterSpec paramSpec = receiverKey.getParams();
        String name = EllipticCurves.getName(paramSpec.getCurve());
        if (EllipticCurves.SECP_256K1.equals(name))
        {
            // https://www.rfc-editor.org/rfc/rfc8812.html#name-other-uses-of-the-secp256k1 kinda says not to do it
            // so explicitly disallow it
            throw new InvalidKeyException("Use of the " + EllipticCurves.SECP_256K1 + " curve is not defined for ECDH-ES key agreement with JOSE.");
        }
    }

    ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, PublicJsonWebKey ephemeralJwk, ProviderContext providerContext) throws JoseException
    {
        headers.setJwkHeaderValue(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY, ephemeralJwk);
        byte[] z = generateEcdhSecret(ephemeralJwk.getPrivateKey(), (PublicKey) managementKey, providerContext);
        byte[] derivedKey = kdf(cekDesc, headers, z, providerContext);
        return new ContentEncryptionKeys(derivedKey, null);
    }

    public CryptoPrimitive prepareForDecrypt(Key managementKey, Headers headers, ProviderContext providerContext) throws JoseException
    {
        String keyFactoryProvider = providerContext.getGeneralProviderContext().getKeyFactoryProvider();
        PublicJsonWebKey ephemeralJwk = headers.getPublicJwkHeaderValue(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY, keyFactoryProvider);

        PublicKey ephemeralPublicKey = ephemeralJwk.getPublicKey();
        PrivateKey privateKey = (PrivateKey) managementKey;

        if (ephemeralPublicKey instanceof ECPublicKey)
        {
            ECPublicKey ecEphemeralPublicKey = (ECPublicKey) ephemeralPublicKey;
            ECPrivateKey ecPrivateKey = (ECPrivateKey) managementKey;
            checkCurveAllowed(ecPrivateKey);
            checkPointIsOnCurve(ecEphemeralPublicKey, ecPrivateKey);
        }
        KeyAgreement keyAgreement = createKeyAgreement(privateKey, ephemeralPublicKey, providerContext);
        return new CryptoPrimitive(keyAgreement);
    }

    public Key manageForDecrypt(CryptoPrimitive cryptoPrimitive, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers,  ProviderContext providerContext) throws JoseException
    {
        KeyAgreement keyAgreement = cryptoPrimitive.getKeyAgreement();
        byte[] z = keyAgreement.generateSecret();
        byte[] derivedKey = kdf(cekDesc, headers, z, providerContext);
        String cekAlg = cekDesc.getContentEncryptionKeyAlgorithm();
        return new SecretKeySpec(derivedKey, cekAlg);
    }

    private void checkPointIsOnCurve(ECPublicKey ephemeralPublicKey, ECPrivateKey privateKey) throws JoseException
    {
        // to prevent 'Invalid Curve Attack': for NIST curves, check whether public key is on the private key's curve.
        // from https://www.cs.bris.ac.uk/Research/CryptographySecurity/RWC/2017/nguyen.quan.pdf

        // there appear to be similar checks in the JVM starting with 1.8.0_51 but
        // doing it here explicitly seems prudent

        // (y^2) mod p = (x^3 + ax + b) mod p
        // thanks to Antonio Sanso for guidance on how to do this check
        ECParameterSpec ecParameterSpec = privateKey.getParams();
        EllipticCurve curve = ecParameterSpec.getCurve();
        ECPoint point = ephemeralPublicKey.getW();
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        BigInteger leftSide = (y.pow(2)).mod(p);
        BigInteger rightSide = (x.pow(3).add(a.multiply(x)).add(b)).mod(p);
        boolean onCurve = leftSide.equals(rightSide);
        if (!onCurve)
        {
            throw new InvalidKeyException(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY + " is invalid for " + EllipticCurves.getName(curve));
        }
    }

    private byte[] kdf(ContentEncryptionKeyDescriptor cekDesc, Headers headers, byte[] z, ProviderContext providerContext)
    {
        String messageDigestProvider = providerContext.getGeneralProviderContext().getMessageDigestProvider();
        KdfUtil kdf = new KdfUtil(messageDigestProvider);
        int keydatalen = ByteUtil.bitLength(cekDesc.getContentEncryptionKeyByteLength());
        /*
           AlgorithmID  In the Direct Key Agreement case, this is set to the
          octets of the UTF-8 representation of the "enc" header parameter
          value.  In the Key Agreement with Key Wrapping case, this is set
          to the octets of the UTF-8 representation of the "alg" header
          parameter value.*/
        String algorithmID = headers.getStringHeaderValue(algorithmIdHeaderName);
        String partyUInfo = headers.getStringHeaderValue(HeaderParameterNames.AGREEMENT_PARTY_U_INFO);
        String partyVInfo = headers.getStringHeaderValue(HeaderParameterNames.AGREEMENT_PARTY_V_INFO);
        return kdf.kdf(z, keydatalen, algorithmID, partyUInfo, partyVInfo);
    }


    private KeyAgreement getKeyAgreement(String provider, String javaAlgorithm) throws JoseException
    {
        try
        {
            return provider == null ? KeyAgreement.getInstance(javaAlgorithm) : KeyAgreement.getInstance(javaAlgorithm, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new UncheckedJoseException("No " + javaAlgorithm + " KeyAgreement available.", e);
        }
        catch (NoSuchProviderException e)
        {
            throw new JoseException("Cannot get "+javaAlgorithm+ " KeyAgreement with provider " + provider, e);
        }
    }

    private KeyAgreement createKeyAgreement(PrivateKey privateKey, PublicKey publicKey, ProviderContext providerContext) throws JoseException
    {
        String keyAgreementProvider = providerContext.getSuppliedKeyProviderContext().getKeyAgreementProvider();
        String javaName = (privateKey instanceof ECPrivateKey) ? getJavaAlgorithm() : "XDH";
        KeyAgreement keyAgreement = getKeyAgreement(keyAgreementProvider, javaName);

        try
        {
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
        }
        catch (java.security.InvalidKeyException e)
        {
            throw new InvalidKeyException("Invalid Key for " + getJavaAlgorithm() + " key agreement - " + e, e);
        }

        return keyAgreement;
    }

    private byte[] generateEcdhSecret(PrivateKey privateKey, PublicKey publicKey, ProviderContext providerContext) throws JoseException
    {
        KeyAgreement keyAgreement = createKeyAgreement(privateKey, publicKey, providerContext);
        return keyAgreement.generateSecret();
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        if (!(managementKey instanceof ECPublicKey || XDHKeyUtil.isXECPublicKey(managementKey)))
        {
            throw new InvalidKeyException("Encrypting with ECDH expects ECPublicKey or XECPublicKey but was given " + managementKey);
        }
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        if (!(managementKey instanceof ECPrivateKey || XDHKeyUtil.isXECPrivateKey(managementKey)))
        {
            throw new InvalidKeyException("Decrypting with ECDH expects ECPrivateKey or XECPrivateKey but was given " + managementKey);
        }
    }

    @Override
    public boolean isAvailable()
    {
        EcKeyUtil ecKeyUtil = new EcKeyUtil();
        return ecKeyUtil.isAvailable() && AlgorithmAvailability.isAvailable("KeyAgreement", getJavaAlgorithm());
    }
}
