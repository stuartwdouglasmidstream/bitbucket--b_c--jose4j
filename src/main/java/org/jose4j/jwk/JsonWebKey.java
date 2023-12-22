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

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.HashUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.JsonHelp;
import org.jose4j.lang.StringUtil;

import java.io.Serializable;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.jose4j.lang.HashUtil.SHA_256;

/**
 */
public abstract class JsonWebKey implements Serializable
{
    public enum OutputControlLevel {INCLUDE_PRIVATE, INCLUDE_SYMMETRIC, PUBLIC_ONLY}

    public static final String KEY_TYPE_PARAMETER = "kty";
    public static final String USE_PARAMETER = "use";
    public static final String KEY_ID_PARAMETER = "kid";
    public static final String ALGORITHM_PARAMETER = "alg";
    public static final String KEY_OPERATIONS = "key_ops";

    private String use;
    private String keyId;
    private String algorithm;

    private List<String> keyOps;

    protected Map<String, Object> otherParameters = new LinkedHashMap<>();

    protected Key key;

    protected JsonWebKey(Key key)
    {
        this.key = key;
    }

    protected JsonWebKey(Map<String, Object> params) throws JoseException
    {
        otherParameters.putAll(params);
        removeFromOtherParams(KEY_TYPE_PARAMETER, USE_PARAMETER, KEY_ID_PARAMETER, ALGORITHM_PARAMETER, KEY_OPERATIONS);
        setUse(getString(params, USE_PARAMETER));
        setKeyId(getString(params, KEY_ID_PARAMETER));
        setAlgorithm(getString(params, ALGORITHM_PARAMETER));
        if (params.containsKey(KEY_OPERATIONS))
        {
             keyOps = JsonHelp.getStringArray(params, KEY_OPERATIONS);
        }
    }

    public abstract String getKeyType();
    protected abstract void fillTypeSpecificParams(Map<String,Object> params, OutputControlLevel outputLevel);

    /**
     * @deprecated deprecated in favor {@link #getKey()} or {@link PublicJsonWebKey#getPublicKey()}
     * @return PublicKey
     */
    public PublicKey getPublicKey()
    {
        try
        {
            return (PublicKey) key;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public Key getKey()
    {
        return key;
    }

    public String getUse()
    {
        return use;
    }

    public void setUse(String use)
    {
        this.use = use;
    }

    public String getKeyId()
    {
        return keyId;
    }

    public void setKeyId(String keyId)
    {
        this.keyId = keyId;
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public void setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
    }

    public List<String> getKeyOps()
    {
        return keyOps;
    }

    public void setKeyOps(List<String> keyOps)
    {
        this.keyOps = keyOps;
    }

    public void setOtherParameter(String name, Object value)
    {
        otherParameters.put(name, value);
    }

    public <T> T getOtherParameterValue(String name, Class<T> type)
    {
        Object o = otherParameters.get(name);
        return type.cast(o);
    }

    protected void removeFromOtherParams(String... names)
    {
        for (String name : names)
        {
            otherParameters.remove(name);
        }
    }

    public Map<String, Object> toParams(OutputControlLevel outputLevel)
    {
        Map<String, Object> params = new LinkedHashMap<String, Object>();
        params.put(KEY_TYPE_PARAMETER, getKeyType());
        putIfNotNull(KEY_ID_PARAMETER, getKeyId(), params);
        putIfNotNull(USE_PARAMETER, getUse(), params);
        putIfNotNull(KEY_OPERATIONS, keyOps, params);
        putIfNotNull(ALGORITHM_PARAMETER, getAlgorithm(), params);
        fillTypeSpecificParams(params, outputLevel);
        params.putAll(otherParameters);
        return params;
    }

    public String toJson()
    {
        return toJson(OutputControlLevel.INCLUDE_SYMMETRIC);
    }

    public String toJson(OutputControlLevel outputLevel)
    {
        Map<String, Object> params = toParams(outputLevel);
        return JsonUtil.toJson(params);
    }

    @Override
    public String toString()
    {
        return getClass().getName() + toParams(OutputControlLevel.PUBLIC_ONLY);
    }

    public String calculateBase64urlEncodedThumbprint(String hashAlgorithm)
    {
        byte[] thumbprint = calculateThumbprint(hashAlgorithm);
        return Base64Url.encode(thumbprint);
    }

    public byte[] calculateThumbprint(String hashAlgorithm)
    {
        MessageDigest digest = HashUtil.getMessageDigest(hashAlgorithm);
        String hashInputString = produceThumbprintHashInput();
        byte[] hashInputBytes = StringUtil.getBytesUtf8(hashInputString);
        return digest.digest(hashInputBytes);
    }

	public String calculateThumbprintUri(String hashAlgorithm) {
		if (!hashAlgorithm.equals(SHA_256)) {
			throw new UnsupportedOperationException(
					"Only SHA-256 algorithm supported at this time for Thumbprint URIs");
		}
		return "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + calculateBase64urlEncodedThumbprint(hashAlgorithm);
	}

    protected abstract String produceThumbprintHashInput();

    protected void putIfNotNull(String name, Object value, Map<String, Object> params)
    {
        if (value != null)
        {
            params.put(name,value);
        }
    }

    protected static String getString(Map<String, Object> params, String name) throws JoseException
    {
        return JsonHelp.getStringChecked(params, name);
    }

    protected static String getStringRequired(Map<String, Object> params, String name) throws JoseException
    {
        return getString(params, name, true);
    }

    protected static String getString(Map<String, Object> params, String name, boolean required) throws JoseException
    {
        String value = getString(params, name);
        if (value == null && required)
        {
            throw new JoseException("Missing required '" + name + "' parameter.");
        }

        return value;
    }

    public static class Factory
    {
        public static JsonWebKey newJwk(Map<String,Object> params) throws JoseException
        {
            String kty = getStringRequired(params, KEY_TYPE_PARAMETER);

            switch (kty)
            {
                case RsaJsonWebKey.KEY_TYPE:
                    return new RsaJsonWebKey(params);
                case EllipticCurveJsonWebKey.KEY_TYPE:
                    return new EllipticCurveJsonWebKey(params);
                case OctetKeyPairJsonWebKey.KEY_TYPE:
                    return new OctetKeyPairJsonWebKey(params);
                case OctetSequenceJsonWebKey.KEY_TYPE:
                    return new OctetSequenceJsonWebKey(params);
                default:
                    throw new JoseException("Unknown key type algorithm: '" + kty + "'");
            }
        }

        public static JsonWebKey newJwk(Key key) throws JoseException
        {
            if (RSAPublicKey.class.isInstance(key))
            {
                return new RsaJsonWebKey((RSAPublicKey)key);
            }
            else if (ECPublicKey.class.isInstance(key))
            {
                return new EllipticCurveJsonWebKey((ECPublicKey)key);
            }
            else if (PublicKey.class.isInstance(key))
            {
                if (OctetKeyPairJsonWebKey.isApplicable(key))
                {
                    return new OctetKeyPairJsonWebKey((PublicKey)key);
                }

                throw new JoseException("Unsupported or unknown public key (alg=" + key.getAlgorithm() +") " + key);
            }
            else if (PrivateKey.class.isInstance(key))
            {
                throw new JoseException("A JsonWebKey instance needs to be created from a public or symmetric key.");
            }
            else
            {
                return new OctetSequenceJsonWebKey(key);
            }
        }

        public static JsonWebKey newJwk(String json) throws JoseException
        {
            Map<String, Object> parsed = JsonUtil.parseJson(json);
            return newJwk(parsed);
        }
    }
}
