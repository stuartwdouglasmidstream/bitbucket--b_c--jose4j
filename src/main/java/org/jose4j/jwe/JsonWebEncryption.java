/*
 * Copyright 2012-2013 Brian Campbell
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
import org.jose4j.jwa.AlgorithmFactory;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;
import org.jose4j.zip.CompressionAlgorithm;

import java.security.Key;

/**
 */
public class JsonWebEncryption extends JsonWebStructure
{
    private Base64Url base64url = new Base64Url();
    
    private String plaintextCharEncoding = StringUtil.UTF_8;
    private byte[] plaintext;

    byte[] encryptedKey;
    byte[] iv;
    byte[] ciphertext;

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

    public void setEncryptionMethodHeaderParameter(String enc)
    {
        setHeader(HeaderParameterNames.ENCRYPTION_METHOD, enc);
    }

    public String getEncryptionMethodHeaderParameter()
    {
        return getHeader(HeaderParameterNames.ENCRYPTION_METHOD);
    }

    public ContentEncryptionAlgorithm getContentEncryptionAlgorithm() throws JoseException
    {
        String encValue = getEncryptionMethodHeaderParameter();
        if (encValue == null)
        {
            throw new JoseException(HeaderParameterNames.ENCRYPTION_METHOD + " header not set.");
        }
        AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
        AlgorithmFactory<ContentEncryptionAlgorithm> factory = factoryFactory.getJweContentEncryptionAlgorithmFactory();
        return factory.getAlgorithm(encValue);
    }

    public KeyManagementAlgorithm getKeyManagementModeAlgorithm() throws JoseException
    {
        String algo = getAlgorithmHeaderValue();
        if (algo == null)
        {
            throw new JoseException(HeaderParameterNames.ALGORITHM + " header not set.");
        }
        AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
        AlgorithmFactory<KeyManagementAlgorithm> factory = factoryFactory.getJweKeyManagementAlgorithmFactory();
        return factory.getAlgorithm(algo);
    }

    public void setCompactSerialization(String compactSerialization) throws JoseException
    {
        String[] parts = CompactSerializer.deserialize(compactSerialization);
        setEncodedHeader(parts[0]);
        encryptedKey = base64url.base64UrlDecode(parts[1]);
        iv = base64url.base64UrlDecode(parts[2]);
        String encodedCiphertext = parts[3];
        checkNotEmptyPart(encodedCiphertext, "Encoded JWE Ciphertext");
        ciphertext = base64url.base64UrlDecode(encodedCiphertext);
        String encodedAuthenticationTag = parts[4];
        checkNotEmptyPart(encodedAuthenticationTag, "Encoded JWE Authentication Tag");
        byte[] tag = base64url.base64UrlDecode(encodedAuthenticationTag);
        setIntegrity(tag);
    }

    private void decrypt() throws JoseException
    {
        KeyManagementAlgorithm keyManagementModeAlg = getKeyManagementModeAlgorithm();
        ContentEncryptionAlgorithm contentEncryptionAlg = getContentEncryptionAlgorithm();

        ContentEncryptionKeyDescriptor contentEncryptionKeyDesc = contentEncryptionAlg.getContentEncryptionKeyDescriptor();

        if (isDoKeyValidation())
        {
            keyManagementModeAlg.validateDecryptionKey(getKey(), contentEncryptionAlg);
        }

        Key cek = keyManagementModeAlg.manageForDecrypt(getKey(), encryptedKey, contentEncryptionKeyDesc, getHeaders());

        ContentEncryptionParts contentEncryptionParts = new ContentEncryptionParts(iv, ciphertext, getIntegrity());
        byte[] aad = getEncodedHeaderAsciiBytesForAdditionalAuthenticatedData();
        byte[] decrypted = contentEncryptionAlg.decrypt(contentEncryptionParts, aad, cek.getEncoded(), getHeaders());

        decrypted = decompress(getHeaders(), decrypted);

        setPlaintext(decrypted);
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

    byte[] compress(Headers headers, byte[] data) throws JoseException
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

        ContentEncryptionKeys contentEncryptionKeys = keyManagementModeAlg.manageForEncrypt(managementKey, contentEncryptionKeyDesc, getHeaders());

        byte[] aad = getEncodedHeaderAsciiBytesForAdditionalAuthenticatedData();
        byte[] contentEncryptionKey = contentEncryptionKeys.getContentEncryptionKey();

        byte[] plaintextBytes = getPlaintextBytes();

        plaintextBytes = compress(getHeaders(), plaintextBytes);

        ContentEncryptionParts contentEncryptionParts = contentEncryptionAlg.encrypt(plaintextBytes, aad, contentEncryptionKey, getHeaders());

        String encodedIv = base64url.base64UrlEncode(contentEncryptionParts.getIv());
        String encodedCiphertext = base64url.base64UrlEncode(contentEncryptionParts.getCiphertext());
        String encodedTag = base64url.base64UrlEncode(contentEncryptionParts.getAuthenticationTag());


        byte[] encryptedKey = contentEncryptionKeys.getEncryptedKey();
        String encodedEncryptedKey = base64url.base64UrlEncode(encryptedKey);

        return CompactSerializer.serialize(getEncodedHeader(), encodedEncryptedKey, encodedIv, encodedCiphertext, encodedTag);
    }
}
