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

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;

import java.util.Map;


/**
 *
 */
class SelectorSupport
{
    private static final String[] VERIFY_OPS = new String[] {KeyOperations.VERIFY};
    private static final String[] DECRYPT_OPS = new String[] {KeyOperations.DECRYPT, KeyOperations.DERIVE_KEY, KeyOperations.UNWRAP_KEY};

    public static SimpleJwkFilter filterForInboundSigned(JsonWebSignature jws) throws JoseException
    {
        SimpleJwkFilter filter = commonFilterForInbound(jws);
        filter.setUse(Use.SIGNATURE, SimpleJwkFilter.OMITTED_OKAY);
        filter.setKeyOperations(VERIFY_OPS, SimpleJwkFilter.OMITTED_OKAY);
        return filter;
    }

    public static SimpleJwkFilter filterForInboundEncrypted(JsonWebEncryption jwe) throws JoseException
    {
        SimpleJwkFilter filter = commonFilterForInbound(jwe);
        filter.setUse(Use.ENCRYPTION, SimpleJwkFilter.OMITTED_OKAY);
        filter.setKeyOperations(DECRYPT_OPS, SimpleJwkFilter.OMITTED_OKAY);

        // Originally the ECDH JWE algs implied only the "EC" key type but with RFC 8037 it can now also be "OKP".
        // This is a 'workaround' (could be addressed at a more fundamental level and maybe will need to be eventually)
        // to get decryption JWK resolution to function with OKP type keys and ECDH-ES* by using the typ value
        // from the epk header as filter criteria.
        String algorithmIdentifier = jwe.getAlgorithmNoConstraintCheck().getAlgorithmIdentifier();
        if (algorithmIdentifier.startsWith(KeyManagementAlgorithmIdentifiers.ECDH_ES))
        {
            Object objectHeaderValue = jwe.getHeaders().getObjectHeaderValue(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY);

            if (objectHeaderValue instanceof Map)
            {
                Map<String, Object> jwkParams = (Map<String, Object>) objectHeaderValue;
                Object ktyObj = jwkParams.get(JsonWebKey.KEY_TYPE_PARAMETER);
                if (ktyObj instanceof String)
                {
                    filter.setKty((String) ktyObj);
                }
            }
        }

        return filter;
    }

    private static SimpleJwkFilter commonFilterForInbound(JsonWebStructure jwx) throws JoseException
    {
        SimpleJwkFilter filter = new SimpleJwkFilter();
        String kid = jwx.getKeyIdHeaderValue();
        if (kid != null)
        {
            filter.setKid(kid, SimpleJwkFilter.VALUE_REQUIRED);
        }

        String x5t = jwx.getX509CertSha1ThumbprintHeaderValue();
        String x5tS256 = jwx.getX509CertSha256ThumbprintHeaderValue();
        filter.setAllowFallbackDeriveFromX5cForX5Thumbs(true);
        if (x5t != null)
        {
            filter.setX5t(x5t, SimpleJwkFilter.OMITTED_OKAY);
        }
        if (x5tS256 != null)
        {
            filter.setX5tS256(x5tS256, SimpleJwkFilter.OMITTED_OKAY);
        }

        String keyType = jwx.getAlgorithmNoConstraintCheck().getKeyType();
        filter.setKty(keyType);

        return filter;
    }


}
