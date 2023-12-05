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
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmFactory;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;
import org.jose4j.zip.CompressionAlgorithm;
import org.jose4j.zip.CompressionAlgorithmIdentifiers;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.security.Key;

/**
 */
public class JsonWebEncryption extends JsonWebStructure
{
	public static final short COMPACT_SERIALIZATION_PARTS = 5;
    private static final AlgorithmConstraints DEFAULT_BLOCKED =
            new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLOCK,
                    KeyManagementAlgorithmIdentifiers.RSA1_5,
                    KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW,
                    KeyManagementAlgorithmIdentifiers.PBES2_HS384_A192KW,
                    KeyManagementAlgorithmIdentifiers.PBES2_HS512_A256KW);

    private Base64Url base64url = new Base64Url();
    
    private String plaintextCharEncoding = StringUtil.UTF_8;
    private byte[] plaintext;

    byte[] encryptedKey;
    byte[] iv;
    byte[] ciphertext;

    byte[] contentEncryptionKey;

    private AlgorithmConstraints contentEncryptionAlgorithmConstraints = AlgorithmConstraints.NO_CONSTRAINTS;

    private CryptoPrimitive decryptingPrimitive;

    public JsonWebEncryption()
    {
        setAlgorithmConstraints(DEFAULT_BLOCKED);
    }

    public void setPlainTextCharEncoding(String plaintextCharEncoding)
    {
        this.plaintextCharEncoding = plaintextCharEncoding;
    }

    public void setPlaintext(byte[] plaintext)
    {
        this.plaintext = plaintext;
    }

    public void setPlaintext(String plaintext)
    {
        this.plaintext = StringUtil.getBytesUnchecked(plaintext, plaintextCharEncoding);
    }

    public String getPlaintextString() throws JoseException
    {
        return StringUtil.newString(getPlaintextBytes(), plaintextCharEncoding);
    }

    public byte[] getPlaintextBytes() throws JoseException
    {
        if (plaintext == null)
        {
            this.decrypt();
        }
        return plaintext;
    }

    @Override
    public String getPayload() throws JoseException
    {
        return getPlaintextString();
    }

    @Override
    public void setPayload(String payload)
    {
        setPlaintext(payload);
    }

    public void setEncryptionMethodHeaderParameter(String enc)
    {
        setHeader(HeaderParameterNames.ENCRYPTION_METHOD, enc);
    }

    public String getEncryptionMethodHeaderParameter()
    {
        return getHeader(HeaderParameterNames.ENCRYPTION_METHOD);
    }

    public void setCompressionAlgorithmHeaderParameter(String zip)
    {
        setHeader(HeaderParameterNames.ZIP, zip);
    }

    public String getCompressionAlgorithmHeaderParameter()
    {
        return getHeader(HeaderParameterNames.ZIP);
    }

    public void enableDefaultCompression()
    {
        setCompressionAlgorithmHeaderParameter(CompressionAlgorithmIdentifiers.DEFLATE);
    }

    public void setContentEncryptionAlgorithmConstraints(AlgorithmConstraints contentEncryptionAlgorithmConstraints)
    {
        this.contentEncryptionAlgorithmConstraints = contentEncryptionAlgorithmConstraints;
    }

    public ContentEncryptionAlgorithm getContentEncryptionAlgorithm() throws InvalidAlgorithmException
    {
        String encValue = getEncryptionMethodHeaderParameter();
        if (encValue == null)
        {
            throw new InvalidAlgorithmException("Content encryption header ("+HeaderParameterNames.ENCRYPTION_METHOD+") not set.");
        }

        contentEncryptionAlgorithmConstraints.checkConstraint(encValue);
        AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
        AlgorithmFactory<ContentEncryptionAlgorithm> factory = factoryFactory.getJweContentEncryptionAlgorithmFactory();
        return factory.getAlgorithm(encValue);
    }

    public KeyManagementAlgorithm getKeyManagementModeAlgorithm() throws InvalidAlgorithmException
    {
        return getKeyManagementModeAlgorithm(true);
    }

    KeyManagementAlgorithm getKeyManagementModeAlgorithm(boolean checkConstraints) throws InvalidAlgorithmException
    {
        String algo = getAlgorithmHeaderValue();
        if (algo == null)
        {
            throw new InvalidAlgorithmException("Encryption key management algorithm header ("+HeaderParameterNames.ALGORITHM+") not set.");
        }

        if (checkConstraints)
        {
            getAlgorithmConstraints().checkConstraint(algo);
        }
        AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
        AlgorithmFactory<KeyManagementAlgorithm> factory = factoryFactory.getJweKeyManagementAlgorithmFactory();
        return factory.getAlgorithm(algo);
    }

    @Override
    public KeyManagementAlgorithm getAlgorithmNoConstraintCheck() throws InvalidAlgorithmException
    {
        return getKeyManagementModeAlgorithm(false);
    }

    @Override
    public KeyManagementAlgorithm getAlgorithm() throws InvalidAlgorithmException
    {
        return getKeyManagementModeAlgorithm();
    }

    protected void setCompactSerializationParts(String[] parts) throws JoseException
    {
        if (parts.length != COMPACT_SERIALIZATION_PARTS)
        {
            throw new JoseException("A JWE Compact Serialization must have exactly " + COMPACT_SERIALIZATION_PARTS + " parts separated by period ('.') characters");
        }

        setEncodedHeader(parts[0]);
        encryptedKey = base64url.base64UrlDecode(parts[1]);
        setEncodedIv(parts[2]);
        String encodedCiphertext = parts[3];
        checkNotEmptyPart(encodedCiphertext, "Encoded JWE Ciphertext");
        ciphertext = base64url.base64UrlDecode(encodedCiphertext);
        String encodedAuthenticationTag = parts[4];
        checkNotEmptyPart(encodedAuthenticationTag, "Encoded JWE Authentication Tag");
        byte[] tag = base64url.base64UrlDecode(encodedAuthenticationTag);
        setIntegrity(tag);
    }

    /**
     * Create, initialize and return the {@link CryptoPrimitive} that
     * this JWE instance will use for agreement or decryption of the content encryption key.
     * This can optionally be called after setting the key (and maybe ProviderContext) but before getting the
     * payload (which is when the decryption magic happens).
     * This method provides access to the underlying primitive instance (e.g. a {@link Cipher}), which allows execution of
     * the operation to be gated by some approval or authorization.
     * For example, signing on Android with a key that was set to require user authentication when created needs a biometric
     * prompt to allow the signature to execute with the key.
     *
     * @return a CryptoPrimitive containing either a {@link Cipher}, {@link KeyAgreement}, etc., or null
     * @throws JoseException if an error condition is encountered during the initialization process
     */
    public CryptoPrimitive prepareDecryptingPrimitive() throws JoseException
    {
        decryptingPrimitive = createDecryptingPrimitive();
        return decryptingPrimitive;
    }

    private CryptoPrimitive createDecryptingPrimitive() throws JoseException
    {
        KeyManagementAlgorithm keyManagementModeAlg = getKeyManagementModeAlgorithm();
        Key managmentKey = getKey();
        if (isDoKeyValidation())
        {
            ContentEncryptionAlgorithm contentEncryptionAlg = getContentEncryptionAlgorithm();
            keyManagementModeAlg.validateDecryptionKey(managmentKey, contentEncryptionAlg);
        }

        return keyManagementModeAlg.prepareForDecrypt(managmentKey, headers, getProviderCtx());
    }

    private void decrypt() throws JoseException
    {
        KeyManagementAlgorithm keyManagementModeAlg = getKeyManagementModeAlgorithm();
        ContentEncryptionAlgorithm contentEncryptionAlg = getContentEncryptionAlgorithm();

        ContentEncryptionKeyDescriptor contentEncryptionKeyDesc = contentEncryptionAlg.getContentEncryptionKeyDescriptor();

        checkCrit();

        CryptoPrimitive cryptoPrimitive = (decryptingPrimitive == null) ? createDecryptingPrimitive() : decryptingPrimitive;

        Key cek = keyManagementModeAlg.manageForDecrypt(cryptoPrimitive, getEncryptedKey(), contentEncryptionKeyDesc, getHeaders(), getProviderCtx());

        ContentEncryptionParts contentEncryptionParts = new ContentEncryptionParts(iv, ciphertext, getIntegrity());
        byte[] aad = getEncodedHeaderAsciiBytesForAdditionalAuthenticatedData();

        byte[] rawCek = cek.getEncoded();
        checkCek(contentEncryptionAlg, contentEncryptionKeyDesc, rawCek);
        byte[] decrypted = contentEncryptionAlg.decrypt(contentEncryptionParts, aad, rawCek, getHeaders(), getProviderCtx());

        decrypted = decompress(getHeaders(), decrypted);

        setPlaintext(decrypted);
    }

    private void checkCek(ContentEncryptionAlgorithm contentEncryptionAlg, ContentEncryptionKeyDescriptor contentEncryptionKeyDesc, byte[] rawCek)
            throws InvalidKeyException
    {
        int contentEncryptionKeyByteLength = contentEncryptionKeyDesc.getContentEncryptionKeyByteLength();
        if (rawCek.length != contentEncryptionKeyByteLength)
        {
            throw new InvalidKeyException(ByteUtil.bitLength(rawCek)
                    + " bit content encryption key is not the correct size for the " + contentEncryptionAlg.getAlgorithmIdentifier()
                    + " content encryption algorithm (" + ByteUtil.bitLength(contentEncryptionKeyByteLength) + ").");
        }
    }

    public byte[] getEncryptedKey()
    {
        return encryptedKey;
    }

    byte[] getEncodedHeaderAsciiBytesForAdditionalAuthenticatedData()
    {
        String encodedHeader = getEncodedHeader();
        return StringUtil.getBytesAscii(encodedHeader);
    }

    byte[] decompress(Headers headers, byte[] data) throws JoseException
    {
        String zipHeaderValue = headers.getStringHeaderValue(HeaderParameterNames.ZIP);
        if (zipHeaderValue != null)
        {
            AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
            AlgorithmFactory<CompressionAlgorithm> zipAlgFactory = factoryFactory.getCompressionAlgorithmFactory();
            CompressionAlgorithm compressionAlgorithm = zipAlgFactory.getAlgorithm(zipHeaderValue);
            data = compressionAlgorithm.decompress(data);
        }
        return data;
    }

    byte[] compress(Headers headers, byte[] data) throws InvalidAlgorithmException
    {
        String zipHeaderValue = headers.getStringHeaderValue(HeaderParameterNames.ZIP);
        if (zipHeaderValue != null)
        {
            AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
            AlgorithmFactory<CompressionAlgorithm> zipAlgFactory = factoryFactory.getCompressionAlgorithmFactory();
            CompressionAlgorithm compressionAlgorithm = zipAlgFactory.getAlgorithm(zipHeaderValue);
            data = compressionAlgorithm.compress(data);
        }
        return data;
    }

    public String getCompactSerialization() throws JoseException
    {
        KeyManagementAlgorithm keyManagementModeAlg = getKeyManagementModeAlgorithm();
        ContentEncryptionAlgorithm contentEncryptionAlg = getContentEncryptionAlgorithm();

        ContentEncryptionKeyDescriptor contentEncryptionKeyDesc = contentEncryptionAlg.getContentEncryptionKeyDescriptor();
        Key managementKey = getKey();
        if (isDoKeyValidation())
        {
            keyManagementModeAlg.validateEncryptionKey(getKey(), contentEncryptionAlg);
        }

        ContentEncryptionKeys contentEncryptionKeys = keyManagementModeAlg.manageForEncrypt(managementKey, contentEncryptionKeyDesc, getHeaders(), contentEncryptionKey, getProviderCtx());
        setContentEncryptionKey(contentEncryptionKeys.getContentEncryptionKey());
        encryptedKey = contentEncryptionKeys.getEncryptedKey();

        byte[] aad = getEncodedHeaderAsciiBytesForAdditionalAuthenticatedData();
        byte[] contentEncryptionKey = contentEncryptionKeys.getContentEncryptionKey();

        byte[] plaintextBytes = this.plaintext;
        if (plaintextBytes == null)
        {
            throw new NullPointerException("The plaintext payload for the JWE has not been set.");
        }

        plaintextBytes = compress(getHeaders(), plaintextBytes);

        checkCek(contentEncryptionAlg, contentEncryptionKeyDesc, contentEncryptionKey);
        ContentEncryptionParts contentEncryptionParts = contentEncryptionAlg.encrypt(plaintextBytes, aad, contentEncryptionKey, getHeaders(), getIv(), getProviderCtx());
        setIv(contentEncryptionParts.getIv());
        ciphertext = contentEncryptionParts.getCiphertext();

        String encodedIv = base64url.base64UrlEncode(contentEncryptionParts.getIv());
        String encodedCiphertext = base64url.base64UrlEncode(contentEncryptionParts.getCiphertext());
        String encodedTag = base64url.base64UrlEncode(contentEncryptionParts.getAuthenticationTag());


        byte[] encryptedKey = contentEncryptionKeys.getEncryptedKey();
        String encodedEncryptedKey = base64url.base64UrlEncode(encryptedKey);

        return CompactSerializer.serialize(getEncodedHeader(), encodedEncryptedKey, encodedIv, encodedCiphertext, encodedTag);
    }

    public byte[] getContentEncryptionKey()
    {
        return contentEncryptionKey;
    }

    public void setContentEncryptionKey(byte[] contentEncryptionKey)
    {
        this.contentEncryptionKey = contentEncryptionKey;
    }

    public void setEncodedContentEncryptionKey(String encodedContentEncryptionKey)
    {
        setContentEncryptionKey(base64url.decode(encodedContentEncryptionKey));
    }

    public byte[] getIv()
    {
        return iv;
    }

    public void setIv(byte[] iv)
    {
        this.iv = iv;
    }

    public void setEncodedIv(String encodedIv)
    {
        setIv(base64url.base64UrlDecode(encodedIv));

    }
}
