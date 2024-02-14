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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 *
 */
public class SimpleJwkFilter
{
    public static boolean OMITTED_OKAY = true;
    public static boolean VALUE_REQUIRED = false;

    private static final String[] EMPTY = new String[2];
    private Criteria kid;
    private MultiValueCriteria kty;
    private Criteria use;
    private Criteria alg;
    private Criteria x5t;
    private Criteria x5tS256;
    private boolean allowThumbsFallbackDeriveFromX5c;
    private MultiValueCriteria keyOps;

    private MultiValueCriteria crv;

    public void setKid(String expectedKid, boolean omittedValueAcceptable)
    {
        kid = new Criteria(expectedKid, omittedValueAcceptable);
    }

    public void setKty(String expectedKty)
    {
        kty = new MultiValueCriteria(new String[] {expectedKty}, false);
    }

    public void setKtys(String[] expectedKtys, boolean omittedValueAcceptable)
    {
        kty = new MultiValueCriteria(expectedKtys, omittedValueAcceptable);
    }

    public void setUse(String expectedUse, boolean omittedValueAcceptable)
    {
        use = new Criteria(expectedUse, omittedValueAcceptable);
    }

    public void setKeyOperations(String[] expectedKeyOps, boolean omittedValueAcceptable)
    {
        keyOps = new MultiValueCriteria(expectedKeyOps, omittedValueAcceptable);
    }

    public void setAlg(String expectedAlg, boolean omittedValueAcceptable)
    {
        alg = new Criteria(expectedAlg, omittedValueAcceptable);
    }

    public void setX5t(String expectedThumb, boolean omittedValueAcceptable)
    {
        x5t = new Criteria(expectedThumb, omittedValueAcceptable);
    }

    public void setX5tS256(String expectedThumb, boolean omittedValueAcceptable)
    {
        x5tS256 = new Criteria(expectedThumb, omittedValueAcceptable);
    }

    public void setAllowFallbackDeriveFromX5cForX5Thumbs(boolean allow)
    {
        this.allowThumbsFallbackDeriveFromX5c = allow;
    }

    public void setCrv(String expectedCrv, boolean omittedValueAcceptable)
    {
        this.crv = new MultiValueCriteria(new String[] {expectedCrv}, omittedValueAcceptable);
    }

    public void setCrvs(String[] expectedCrvs, boolean omittedValueAcceptable)
    {
        this.crv = new MultiValueCriteria(expectedCrvs, omittedValueAcceptable);
    }

    public List<JsonWebKey> filter(Collection<JsonWebKey> jsonWebKeys)
    {
        List<JsonWebKey> filtered = new ArrayList<>();
        for (JsonWebKey jwk : jsonWebKeys)
        {
            boolean match = isMatch(kid, jwk.getKeyId());
            match &= kty == null || kty.meetsCriteria(jwk.getKeyType());
            match &= isMatch(use, jwk.getUse());
            match &= isMatch(alg, jwk.getAlgorithm());
            String[] thumbs = getThumbs(jwk, allowThumbsFallbackDeriveFromX5c);
            match &= isMatch(x5t, thumbs[0]);
            match &= isMatch(x5tS256, thumbs[1]);
            match &= crv == null || crv.meetsCriteria(getCrv(jwk));
            match &= keyOps == null || keyOps.meetsCriteria(jwk.getKeyOps());

            if (match)
            {
                filtered.add(jwk);
            }
        }
        return filtered;
    }

    boolean isMatch(Criteria criteria, String value)
    {
        return (criteria == null) || criteria.meetsCriteria(value);
    }

    String getCrv(JsonWebKey jwk)
    {
        if (jwk instanceof EllipticCurveJsonWebKey)
        {
            return ((EllipticCurveJsonWebKey) jwk).getCurveName();
        }
        else if (jwk instanceof OctetKeyPairJsonWebKey)
        {
            return ((OctetKeyPairJsonWebKey) jwk).getSubtype();
        }

        return null;
    }

    String[] getThumbs(JsonWebKey jwk, boolean allowFallbackDeriveFromX5c)
    {
        if (x5t == null && x5tS256 == null)
        {
            return EMPTY;
        }

        if (jwk instanceof PublicJsonWebKey)
        {
            PublicJsonWebKey publicJwk = (PublicJsonWebKey) jwk;
            String x5t = publicJwk.getX509CertificateSha1Thumbprint(allowFallbackDeriveFromX5c);
            String x5tS256 = publicJwk.getX509CertificateSha256Thumbprint(allowFallbackDeriveFromX5c);

            return new String[] {x5t, x5tS256};
        }
        else
        {
            return EMPTY;
        }
    }

    private static class Criteria
    {
        String value;
        boolean noValueOk;

        private Criteria(String value, boolean noValueOk)
        {
            this.value = value;
            this.noValueOk = noValueOk;
        }

        public boolean meetsCriteria(String value)
        {
            if (value == null)
            {
                return noValueOk;
            }
            else
            {
                return value.equals(this.value);
            }
        }
    }

    private static class MultiValueCriteria
    {
        String[] values;
        boolean noValueOk;

        private MultiValueCriteria(String[] values, boolean noValueOk)
        {
            this.values = values;
            this.noValueOk = noValueOk;
        }

        public boolean meetsCriteria(String value)
        {
            return meetsCriteria(Collections.singletonList(value));
        }

        public boolean meetsCriteria(List<String> values)
        {
            if (values == null)
            {
                return noValueOk;
            }
            else
            {
                for (String value : this.values)
                {
                    if (values.contains(value))
                    {
                        return true;
                    }
                }
                return false;
            }
        }
    }
}
