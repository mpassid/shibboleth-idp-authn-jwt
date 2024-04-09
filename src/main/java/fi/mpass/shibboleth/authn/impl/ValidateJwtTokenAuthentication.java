/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package fi.mpass.shibboleth.authn.impl;

import java.text.ParseException;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
//import javax.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequest;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;

import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.logic.ConstraintViolationException;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * An action that checks for incoming JWT token and produces an
 * {@link net.shibboleth.idp.authn.AuthenticationResult} or records error if the configured user
 * attribute is not existing in the JWT token.
 *  
 * @event {@link EventIds#PROCEED_EVENT_ID}
 * @event {@link EventIds#INVALID_PROFILE_CTX}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class).getAttemptedFlow() != null</pre>
 * @post If AuthenticationContext.getSubcontext(AuthenticationContext.class) != null, then
 * an {@link net.shibboleth.idp.authn.AuthenticationResult} is saved to the {@link AuthenticationContext} on a
 * successful login. On a failed login, the
 * {@link AbstractValidationAction#handleError(ProfileRequestContext, AuthenticationContext, Exception, String)}
 * method is called.
 */
@SuppressWarnings({"unchecked", "rawtypes"})
public class ValidateJwtTokenAuthentication extends AbstractValidationAction {

    /** The default name for the HTTP parameter containing the JWT token. */
    public static final String DEFAULT_JWT_PARAM_NAME = "jwt";
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateJwtTokenAuthentication.class);
    
    /** The JSON field name containing the username in the JWT token. */
    @Nonnull @NotEmpty private String usernameId;
    
    /** The HTTP parameter name containing the raw JWT token. */
    @Nonnull @NotEmpty private final String jwtParameter;

    /** The verifier for the JWT signature. */
    @Nonnull private final JWSVerifier jmsVerifier;
    
    /** Current incoming JWT token, if available. */
    private SignedJWT jwt;
    
    /**
     * Constructor.
     * 
     * @param sharedSecret The shared secret with the issuer of the JWT token.
     */
    public ValidateJwtTokenAuthentication(final String sharedSecret) {
        this(sharedSecret, DEFAULT_JWT_PARAM_NAME);
    }

    /**
     * Constructor.
     * 
     * @param sharedSecret The shared secret with the issuer of the JWT token.
     * @param jwtParam The HTTP parameter name containing the raw JWT token.
     */
    public ValidateJwtTokenAuthentication(final String sharedSecret, final String jwtParam) {
        super();
        Constraint.isNotEmpty(sharedSecret, "sharedSecret cannot be null");
        Constraint.isNotEmpty(jwtParam, "jwtParam cannot be null");
        jwtParameter = jwtParam;
        try {
            jmsVerifier = new MACVerifier(sharedSecret);
        } catch (JOSEException e) {
            log.error("Could not initialize JWT verifier with the given secret", e);
            throw new ConstraintViolationException("Could not initialize JWT verifier!");
        }
    }

    /**
     * Get the attribute name containing the user identifier.
     * @return usernameId.
     */
    public String getUsernameId() {
        return usernameId;
    }
    
    /**
     * Set the attribute name containing the user identifier.
     * @param username The attribute name containing the user identifier.
     */
    public void setUsernameId(String username) {
        ifInitializedThrowUnmodifiabledComponentException();
        Constraint.isNotEmpty(username, "Username cannot be null");
        usernameId = username;
    }
    
    /**
     * Get the current incoming JWT token.
     * @return The current incoming JWT token.
     */
    protected SignedJWT getJwt() {
        return jwt;
    }
    
    /**
     * Set the current incoming JWT token.
     * @param signedJwt What to set.
     */
    protected void setJwt(SignedJWT signedJwt) {
        jwt = signedJwt;
    }
    
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }
        log.trace("{}: Prerequisities fulfilled to start doPreExecute", getLogPrefix());

        final HttpServletRequest servletRequest = getHttpServletRequest();
        if (servletRequest == null) {
            log.error("{} No HttpServletRequst available within profile context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        if (StringSupport.trimOrNull(servletRequest.getParameter(jwtParameter)) == null) {
            log.warn("{} No JWT token available in the request with parameter {}", getLogPrefix(), jwtParameter);
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;            
        }

        log.trace("{}: doPreExecute returning true", getLogPrefix());
        return true;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        final HttpServletRequest servletRequest = getHttpServletRequest();
        try {
            setJwt(SignedJWT.parse(servletRequest.getParameter(jwtParameter)));
            if (!getJwt().verify(jmsVerifier)) {
                log.warn("{}: Invalid signature in the incoming JWT token!", getLogPrefix());
                handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                        AuthnEventIds.NO_CREDENTIALS);
                return;                            
            }
        } catch (ParseException | JOSEException e) {
            log.warn("Could not parse or verify the incoming JWT token", e);
            handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                    AuthnEventIds.NO_CREDENTIALS);
            return;            
        }
        final Object username = getJwt().getPayload().toJSONObject().get(usernameId);
        if (username == null || StringSupport.trimOrNull(String.valueOf(username)) == null) {
            handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                    AuthnEventIds.NO_CREDENTIALS);
            return;            
        }
        log.trace("{}: Building authentication result for user {}", getLogPrefix(), username);
        buildAuthenticationResult(profileRequestContext, authenticationContext);
    }    
    
    /** {@inheritDoc} */
    @Override
    @Nonnull protected Subject populateSubject(@Nonnull final Subject subject) {
        subject.getPrincipals().add(
                new UsernamePrincipal(String.valueOf(getJwt().getPayload().toJSONObject().get(usernameId))));
        log.trace("{}: Subject successfully populated", getLogPrefix());
        return subject;
    }    
}