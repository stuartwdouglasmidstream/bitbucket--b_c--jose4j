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

import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.keys.resolvers.DecryptionKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static org.jose4j.jws.AlgorithmIdentifiers.NONE;
import static org.jose4j.jwt.consumer.ErrorCodes.*;

/**
 *
 */
public class JwtConsumer
{
    private VerificationKeyResolver verificationKeyResolver;
    private DecryptionKeyResolver decryptionKeyResolver;

    private List<ErrorCodeValidator> validators;

    private AlgorithmConstraints jwsAlgorithmConstraints;
    private AlgorithmConstraints jweAlgorithmConstraints;
    private AlgorithmConstraints jweContentEncryptionAlgorithmConstraints;

    private boolean requireSignature = true;
    private boolean requireEncryption;
    private boolean requireIntegrity;

    private boolean liberalContentTypeHandling;

    private boolean skipSignatureVerification;

    private boolean relaxVerificationKeyValidation;

    private boolean skipVerificationKeyResolutionOnNone;

    private boolean relaxDecryptionKeyValidation;

    private ProviderContext jwsProviderContext;
    private ProviderContext jweProviderContext;

    private JwsCustomizer jwsCustomizer;
    private JweCustomizer jweCustomizer;

    JwtConsumer()
    {
    }

    void setJwsAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        this.jwsAlgorithmConstraints = constraints;
    }

    void setJweAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        this.jweAlgorithmConstraints = constraints;
    }

    void setJweContentEncryptionAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        this.jweContentEncryptionAlgorithmConstraints = constraints;
    }

    void setVerificationKeyResolver(VerificationKeyResolver verificationKeyResolver)
    {
        this.verificationKeyResolver = verificationKeyResolver;
    }

    void setDecryptionKeyResolver(DecryptionKeyResolver decryptionKeyResolver)
    {
        this.decryptionKeyResolver = decryptionKeyResolver;
    }

    void setValidators(List<ErrorCodeValidator> validators)
    {
        this.validators = validators;
    }

    void setRequireSignature(boolean requireSignature)
    {
        this.requireSignature = requireSignature;
    }

    void setRequireEncryption(boolean requireEncryption)
    {
        this.requireEncryption = requireEncryption;
    }

    void setRequireIntegrity(boolean requireIntegrity)
    {
        this.requireIntegrity = requireIntegrity;
    }

    void setLiberalContentTypeHandling(boolean liberalContentTypeHandling)
    {
        this.liberalContentTypeHandling = liberalContentTypeHandling;
    }

    void setSkipSignatureVerification(boolean skipSignatureVerification)
    {
        this.skipSignatureVerification = skipSignatureVerification;
    }

    void setRelaxVerificationKeyValidation(boolean relaxVerificationKeyValidation)
    {
        this.relaxVerificationKeyValidation = relaxVerificationKeyValidation;
    }

    public void setSkipVerificationKeyResolutionOnNone(boolean skipVerificationKeyResolutionOnNone)
    {
        this.skipVerificationKeyResolutionOnNone = skipVerificationKeyResolutionOnNone;
    }

    void setRelaxDecryptionKeyValidation(boolean relaxDecryptionKeyValidation)
    {
        this.relaxDecryptionKeyValidation = relaxDecryptionKeyValidation;
    }

    void setJwsProviderContext(ProviderContext jwsProviderContext)
    {
        this.jwsProviderContext = jwsProviderContext;
    }

    void setJweProviderContext(ProviderContext jweProviderContext)
    {
        this.jweProviderContext = jweProviderContext;
    }

    void setJwsCustomizer(JwsCustomizer jwsCustomizer)
    {
        this.jwsCustomizer = jwsCustomizer;
    }

    void setJweCustomizer(JweCustomizer jweCustomizer)
    {
        this.jweCustomizer = jweCustomizer;
    }

    public JwtClaims processToClaims(String jwt) throws InvalidJwtException
    {
        return process(jwt).getJwtClaims();
    }

    public void processContext(JwtContext jwtContext) throws InvalidJwtException
    {
        boolean hasSignature = false;
        boolean hasEncryption = false;
        boolean hasSymmetricEncryption = false;

        ArrayList<JsonWebStructure> originalJoseObjects = new ArrayList<>(jwtContext.getJoseObjects());

        for (int idx = originalJoseObjects.size() - 1 ; idx >= 0 ; idx--)
        {
            List<JsonWebStructure> joseObjects = originalJoseObjects.subList(idx+1, originalJoseObjects.size());
            final List<JsonWebStructure> nestingContext = Collections.unmodifiableList(joseObjects);
            JsonWebStructure currentJoseObject = originalJoseObjects.get(idx);

            try
            {
                if (currentJoseObject instanceof JsonWebSignature)
                {
                    JsonWebSignature jws = (JsonWebSignature) currentJoseObject;
                    boolean isNoneAlg = NONE.equals(jws.getAlgorithmHeaderValue());
                    if (!skipSignatureVerification)
                    {
                        if (jwsProviderContext != null)
                        {
                            jws.setProviderContext(jwsProviderContext);
                        }

                        if (relaxVerificationKeyValidation)
                        {
                            jws.setDoKeyValidation(false);
                        }

                        if (jwsAlgorithmConstraints != null)
                        {
                            jws.setAlgorithmConstraints(jwsAlgorithmConstraints);
                        }

                        if (!isNoneAlg  || !skipVerificationKeyResolutionOnNone)
                        {
                            Key key = verificationKeyResolver.resolveKey(jws, nestingContext);
                            jws.setKey(key);
                        }

                        if (jwsCustomizer != null)
                        {
                            jwsCustomizer.customize(jws, nestingContext);
                        }

                        if (!jws.verifySignature())
                        {
                            throw new InvalidJwtSignatureException(jws, jwtContext);
                        }
                    }


                    if (!isNoneAlg)
                    {
                        hasSignature = true;
                    }

                }
                else
                {
                    JsonWebEncryption jwe = (JsonWebEncryption) currentJoseObject;

                    if (jweAlgorithmConstraints != null)
                    {
                        jweAlgorithmConstraints.checkConstraint(jwe.getAlgorithmHeaderValue());
                    }

                    if (jweContentEncryptionAlgorithmConstraints != null)
                    {
                        jweContentEncryptionAlgorithmConstraints.checkConstraint(jwe.getEncryptionMethodHeaderParameter());
                    }

                    hasEncryption = true;

                    hasSymmetricEncryption = jwe.getKeyManagementModeAlgorithm().getKeyPersuasion() == KeyPersuasion.SYMMETRIC;
                }
            }
            catch (JoseException e)
            {
                StringBuilder sb = new StringBuilder();
                sb.append("Unable to process");
                if (!joseObjects.isEmpty())
                {
                    sb.append(" nested");
                }
                sb.append(" JOSE object (cause: ").append(e).append("): ").append(currentJoseObject);
                ErrorCodeValidator.Error error = new ErrorCodeValidator.Error(ErrorCodes.MISCELLANEOUS, sb.toString());
                throw new InvalidJwtException("JWT processing failed." , error, e, jwtContext);
            }
            catch (InvalidJwtException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                StringBuilder sb = new StringBuilder();
                sb.append("Unexpected exception encountered while processing");
                if (!joseObjects.isEmpty())
                {
                    sb.append(" nested");
                }
                sb.append(" JOSE object (").append(e).append("): ").append(currentJoseObject);
                ErrorCodeValidator.Error error = new ErrorCodeValidator.Error(ErrorCodes.MISCELLANEOUS, sb.toString());
                throw new InvalidJwtException("JWT processing failed." , error, e, jwtContext);
            }
        }


        if (requireSignature && !hasSignature)
        {
            List<ErrorCodeValidator.Error> errors = Collections.singletonList(new ErrorCodeValidator.Error(SIGNATURE_MISSING, "Missing signature."));
            throw new InvalidJwtException("The JWT has no signature but the JWT Consumer is configured to require one: " + jwtContext.getJwt(), errors, jwtContext);
        }

        if (requireEncryption && !hasEncryption)
        {
            List<ErrorCodeValidator.Error> errors = Collections.singletonList(new ErrorCodeValidator.Error(ENCRYPTION_MISSING, "No encryption."));
            throw new InvalidJwtException("The JWT has no encryption but the JWT Consumer is configured to require it: " + jwtContext.getJwt(), errors, jwtContext);
        }

        if (requireIntegrity && !hasSignature && !hasSymmetricEncryption)
        {
            List<ErrorCodeValidator.Error> errors = Collections.singletonList(new ErrorCodeValidator.Error(ErrorCodes.INTEGRITY_MISSING, "Missing Integrity Protection"));
            throw new InvalidJwtException("The JWT has no integrity protection (signature/MAC or symmetric AEAD encryption) " +
                    "but the JWT Consumer is configured to require it: " + jwtContext.getJwt(), errors, jwtContext);
        }

        validate(jwtContext);
    }

    public JwtContext process(String jwt) throws InvalidJwtException
    {
        String workingJwt = jwt;
        JwtClaims jwtClaims = null;
        LinkedList<JsonWebStructure> joseObjects = new LinkedList<>();

        JwtContext jwtContext = new JwtContext(jwt, null, Collections.unmodifiableList(joseObjects));

        while (jwtClaims == null)
        {
            JsonWebStructure joseObject;
            try
            {
                joseObject = JsonWebStructure.fromCompactSerialization(workingJwt);
                String payload;
                if (joseObject instanceof JsonWebSignature)
                {
                    JsonWebSignature jws = (JsonWebSignature) joseObject;
                    payload = jws.getUnverifiedPayload();
                }
                else
                {
                    JsonWebEncryption jwe = (JsonWebEncryption) joseObject;

                    if (jweProviderContext != null)
                    {
                        jwe.setProviderContext(jweProviderContext);
                    }

                    if (relaxDecryptionKeyValidation)
                    {
                        jwe.setDoKeyValidation(false);
                    }

                    if (jweContentEncryptionAlgorithmConstraints != null)
                    {
                        jwe.setContentEncryptionAlgorithmConstraints(jweContentEncryptionAlgorithmConstraints);
                    }

                    final List<JsonWebStructure> nestingContext = Collections.unmodifiableList(joseObjects);
                    Key key = decryptionKeyResolver.resolveKey(jwe, nestingContext);
                    jwe.setKey(key);
                    if (jweAlgorithmConstraints != null)
                    {
                        jwe.setAlgorithmConstraints(jweAlgorithmConstraints);
                    }

                    if (jweCustomizer != null)
                    {
                        jweCustomizer.customize(jwe, nestingContext);
                    }

                    payload = jwe.getPayload();
                }

                if (isNestedJwt(joseObject))
                {
                    workingJwt = payload;
                }
                else
                {
                    try
                    {
                        jwtClaims = JwtClaims.parse(payload, jwtContext);
                        jwtContext.setJwtClaims(jwtClaims);
                    }
                    catch (InvalidJwtException ije)
                    {
                        if (liberalContentTypeHandling)
                        {
                            try
                            {
                                JsonWebStructure.fromCompactSerialization(jwt);
                                workingJwt = payload;
                            }
                            catch (JoseException je)
                            {
                                throw ije;
                            }
                        }
                        else
                        {
                            throw ije;
                        }
                    }
                }

                joseObjects.addFirst(joseObject);
            }
            catch (JoseException e)
            {
                throw newInvalidJwtException("Unable to process", joseObjects, workingJwt, jwtContext, e);
            }
            catch (InvalidJwtException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw newInvalidJwtException("Unexpected exception encountered while processing", joseObjects, workingJwt, jwtContext, e);
            }
        }

        processContext(jwtContext);
        return jwtContext;
    }

    InvalidJwtException newInvalidJwtException(String intro, LinkedList<JsonWebStructure> joseObjects, String workingJwt, JwtContext jwtContext, Exception e)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(intro);
        if (!joseObjects.isEmpty())
        {
            sb.append(" nested (outer object header ");
            sb.append(joseObjects.getFirst().getHeaders().getFullHeaderAsJsonString());
            sb.append(")");
        }
        sb.append(" JOSE object (cause: ").append(e).append("): ").append(workingJwt);
        ErrorCodeValidator.Error error = new ErrorCodeValidator.Error(ErrorCodes.MISCELLANEOUS, sb.toString());
        return new InvalidJwtException("JWT processing failed.", error, e, jwtContext);
    }


    void validate(JwtContext jwtCtx) throws InvalidJwtException
    {
        List<ErrorCodeValidator.Error> issues = new ArrayList<>();
        for (ErrorCodeValidator validator : validators)
        {
            ErrorCodeValidator.Error error;
            try
            {
                error = validator.validate(jwtCtx);
            }
            catch (MalformedClaimException e)
            {
                error = new ErrorCodeValidator.Error(MALFORMED_CLAIM, e.getMessage());
            }
            catch (Exception e)
            {
                String msg = "Unexpected exception thrown from validator " + validator.getClass().getName() + ": " + ExceptionHelp.toStringWithCausesAndAbbreviatedStack(e, this.getClass());
                error = new ErrorCodeValidator.Error(MISCELLANEOUS, msg);
            }

            if (error != null)
            {
                issues.add(error);
            }
        }

        if (!issues.isEmpty())
        {
            String msg = "JWT (claims->" + jwtCtx.getJwtClaims().getRawJson() + ") rejected due to invalid claims or other invalid content.";
            throw new InvalidJwtException(msg, issues, jwtCtx);
        }
    }

    private boolean isNestedJwt(JsonWebStructure joseObject)
    {
        String cty = joseObject.getContentTypeHeaderValue();
        return cty != null && (cty.equalsIgnoreCase("jwt") || cty.equalsIgnoreCase("application/jwt"));
    }

}
