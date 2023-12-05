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

import org.jose4j.base64url.Base64Url;
import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.jwe.kdf.PasswordBasedKeyDerivationFunction2;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.jwx.KeyValidationSupport;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.keys.PbkdfKey;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;
import org.jose4j.mac.MacUtil;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 */
public class Pbes2HmacShaWithAesKeyWrapAlgorithm  extends AlgorithmInfo implements KeyManagementAlgorithm
{
    private static final byte[] ZERO_BYTE = new byte[]{0};

    private AesKeyWrapManagementAlgorithm keyWrap;
    private ContentEncryptionKeyDescriptor keyWrapKeyDescriptor;

    private PasswordBasedKeyDerivationFunction2 pbkdf2;

    // RFC 2898 and JWA both recommend a minimum iteration count of 1000 and mandate at least 8 bytes of salt
    // so we'll go with defaults that somewhat exceed those requirements/recommendations
    private long defaultIterationCount = 8192L * 8;
    private int defaultSaltByteLength = 12;

    private long maxIterationCount = 2499999L;

    public Pbes2HmacShaWithAesKeyWrapAlgorithm(String alg, String hmacAlg, AesKeyWrapManagementAlgorithm keyWrapAlg)
    {
        setAlgorithmIdentifier(alg);
        setJavaAlgorithm("n/a");
        pbkdf2 = new PasswordBasedKeyDerivationFunction2(hmacAlg);
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        setKeyType(PbkdfKey.ALGORITHM);
        keyWrap = keyWrapAlg;
        keyWrapKeyDescriptor = new ContentEncryptionKeyDescriptor(keyWrap.getKeyByteLength(), AesKey.ALGORITHM);
    }

    @Override
    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, byte[] cekOverride, ProviderContext providerContext) throws JoseException
    {
        Key derivedKey = deriveForEncrypt(managementKey, headers, providerContext);
        return keyWrap.manageForEncrypt(derivedKey, cekDesc, headers, cekOverride, providerContext);
    }

    protected Key deriveForEncrypt(Key managementKey, Headers headers, ProviderContext providerContext) throws JoseException
    {
        Long iterationCount = headers.getLongHeaderValue(HeaderParameterNames.PBES2_ITERATION_COUNT);
        if (iterationCount == null)
        {
            iterationCount = defaultIterationCount;
            headers.setObjectHeaderValue(HeaderParameterNames.PBES2_ITERATION_COUNT, iterationCount);
        }

        if (iterationCount < 1000)
        {
            throw new JoseException("iteration count ("+HeaderParameterNames.PBES2_ITERATION_COUNT+"="+
                    iterationCount+") cannot be less than 1000 (and should probably be considerably more)");
        }

        String saltInputString = headers.getStringHeaderValue(HeaderParameterNames.PBES2_SALT_INPUT);
        byte[] saltInput;
        Base64Url base64Url = new Base64Url();
        if (saltInputString == null)
        {
            saltInput = ByteUtil.randomBytes(defaultSaltByteLength, providerContext.getSecureRandom());
            saltInputString = base64Url.base64UrlEncode(saltInput);
            headers.setStringHeaderValue(HeaderParameterNames.PBES2_SALT_INPUT, saltInputString);
        }
        else
        {
            saltInput = base64Url.base64UrlDecode(saltInputString);
        }


        if (saltInput.length < 8)
        {
            throw new JoseException("A p2s salt input value containing 8 or more octets MUST be used.");
        }

        return deriveKey(managementKey, iterationCount, saltInput, providerContext);
    }

    @Override
    public CryptoPrimitive prepareForDecrypt(Key managementKey, Headers headers, ProviderContext providerContext) throws JoseException
    {
        Long iterationCount = headers.getLongHeaderValue(HeaderParameterNames.PBES2_ITERATION_COUNT);
        if (iterationCount > maxIterationCount)
        {
            throw new JoseException("PBES2 iteration count ("+HeaderParameterNames.PBES2_ITERATION_COUNT+"="+
                    iterationCount+") cannot be more than "+ maxIterationCount+" to avoid excessive resource utilization.");
        }
        String saltInputString = headers.getStringHeaderValue(HeaderParameterNames.PBES2_SALT_INPUT);
        Base64Url base64Url = new Base64Url();
        byte[] saltInput = base64Url.base64UrlDecode(saltInputString);
        Key derivedKey = deriveKey(managementKey, iterationCount, saltInput, providerContext);
        return new CryptoPrimitive(derivedKey);
    }

    @Override
    public Key manageForDecrypt(CryptoPrimitive cryptoPrimitive, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, ProviderContext providerContext) throws JoseException
    {
        Key derivedKey = cryptoPrimitive.getKey();
        CryptoPrimitive wrapCryptoPrimitive = keyWrap.prepareForDecrypt(derivedKey, headers, providerContext);
        return keyWrap.manageForDecrypt(wrapCryptoPrimitive, encryptedKey, cekDesc, headers, providerContext);
    }

    private Key deriveKey(Key managementKey, Long iterationCount, byte[] saltInput, ProviderContext providerContext) throws JoseException
    {
        byte[] salt = ByteUtil.concat(StringUtil.getBytesUtf8(getAlgorithmIdentifier()), ZERO_BYTE, saltInput);
        int dkLen = keyWrapKeyDescriptor.getContentEncryptionKeyByteLength();
        String macProvider = providerContext.getSuppliedKeyProviderContext().getMacProvider();
        byte[] derivedKeyBytes = pbkdf2.derive(managementKey.getEncoded(), salt, iterationCount.intValue(), dkLen, macProvider);
        return new SecretKeySpec(derivedKeyBytes, keyWrapKeyDescriptor.getContentEncryptionKeyAlgorithm());
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        validateKey(managementKey);
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        validateKey(managementKey);
    }

    public void validateKey(Key managementKey) throws InvalidKeyException
    {
        KeyValidationSupport.notNull(managementKey);
    }

    @Override
    public boolean isAvailable()
    {
        return keyWrap.isAvailable();
    }

    public long getDefaultIterationCount()
    {
        return defaultIterationCount;
    }

    public void setDefaultIterationCount(long defaultIterationCount)
    {
        this.defaultIterationCount = defaultIterationCount;
    }

    public int getDefaultSaltByteLength()
    {
        return defaultSaltByteLength;
    }

    public void setDefaultSaltByteLength(int defaultSaltByteLength)
    {
        this.defaultSaltByteLength = defaultSaltByteLength;
    }

    public long getMaxIterationCount()
    {
        return maxIterationCount;
    }

    public void setMaxIterationCount(long maxIterationCount)
    {
        this.maxIterationCount = maxIterationCount;
    }

    public static class HmacSha256Aes128 extends Pbes2HmacShaWithAesKeyWrapAlgorithm
    {
        public HmacSha256Aes128()
        {
            super(KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW, MacUtil.HMAC_SHA256, new AesKeyWrapManagementAlgorithm.Aes128().setUseGeneralProviderContext());
        }
    }

    public static class HmacSha384Aes192 extends Pbes2HmacShaWithAesKeyWrapAlgorithm
    {
        public HmacSha384Aes192()
        {
            super(KeyManagementAlgorithmIdentifiers.PBES2_HS384_A192KW, MacUtil.HMAC_SHA384, new AesKeyWrapManagementAlgorithm.Aes192().setUseGeneralProviderContext());
        }
    }

    public static class HmacSha512Aes256 extends Pbes2HmacShaWithAesKeyWrapAlgorithm
    {
        public HmacSha512Aes256()
        {
            super(KeyManagementAlgorithmIdentifiers.PBES2_HS512_A256KW, MacUtil.HMAC_SHA512, new AesKeyWrapManagementAlgorithm.Aes256().setUseGeneralProviderContext());
        }
    }
}
