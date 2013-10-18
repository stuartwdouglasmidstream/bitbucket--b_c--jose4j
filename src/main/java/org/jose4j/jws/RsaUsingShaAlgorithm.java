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

package org.jose4j.jws;

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwx.KeyValidationSupport;
import org.jose4j.lang.JoseException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 */
public class RsaUsingShaAlgorithm extends BaseSignatureAlgorithm implements JsonWebSignatureAlgorithm
{
    public RsaUsingShaAlgorithm(String id, String javaAlgo)
    {
        super(id, javaAlgo, RsaJsonWebKey.KEY_TYPE);
    }

    public void validatePublicKey(PublicKey key) throws JoseException
    {
        KeyValidationSupport.checkRsaKeySize((RSAPublicKey) key);
    }

    public void validatePrivateKey(PrivateKey privateKey) throws JoseException
    {
        KeyValidationSupport.checkRsaKeySize((RSAPrivateKey) privateKey);
    }
}
