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

import java.security.Principal;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.profile.action.EventIds;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;

import fi.mpass.shibboleth.authn.impl.ValidateJwtTokenAuthentication;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.PopulateAuthenticationContextTest;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/**
 * Unit tests for {@link ValidateJwtTokenAuthentication}.
 */
public class ValidateJwtTokenAuthenticationTest extends PopulateAuthenticationContextTest {
    
    /** The action to be tested. */
    private ValidateJwtTokenAuthentication action;
    
    /** The configuration for the attribute containing username. */
    private String uidConfig;
    
    private String sharedSecret;
    
    private String uid;
    
    private int uidNumber;
    
    private String jwtParameterName;
    
    /** {@inheritDoc} */
    @BeforeMethod public void setUp() throws Exception {
        super.setUp();
        uidConfig = "username";
        uid = "mockUser";
        uidNumber = 123;
        jwtParameterName = "jwt";
        sharedSecret = "csdijijpsfohdihioa123hiods324324iho3hiih";
        action = new ValidateJwtTokenAuthentication(sharedSecret, jwtParameterName);
        action.setUsernameId(uidConfig);
        Assert.assertEquals(uidConfig, action.getUsernameId());
        action.setHttpServletRequest((HttpServletRequest) src.getExternalContext().getNativeRequest());
    }

    /**
     * Runs action without attempted flow.
     */
    @Test public void testMissingFlow() throws Exception {
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Attempts to initialize action with invalid shared secret.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testInvalidSecret() throws Exception {
        action = new ValidateJwtTokenAuthentication("not_working");
    }
    
    /**
     * Runs action without JWT token.
     */
    @Test public void testMissingContext() throws Exception {
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }
    
    /**
     * Runs action without {@link HttpServletRequest}.
     */
    @Test public void testMissingServlet() throws Exception {
        action.setHttpServletRequest(null);
        action.initialize();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Runs action with the incoming JWT token that cannot be parsed.
     */
    @Test public void testInvalidJwt() throws Exception {
        final JWSSigner signer = new MACSigner(sharedSecret);
        final JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), 
                new Payload("{ \"" + uidConfig + "\" : \"" + uid + "\" }"));
        jwsObject.sign(signer);
        final String rawJwt = "invalid" + jwsObject.serialize();
        ((MockHttpServletRequest)action.getHttpServletRequest()).addParameter(jwtParameterName, rawJwt);
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with the incoming JWT token signed with different secret.
     */
    @Test public void testInvalidJwtSignature() throws Exception {
        final JWSSigner signer = new MACSigner("abc12" + sharedSecret.substring(5));
        final JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), 
                new Payload("{ \"" + uidConfig + "\" : \"" + uid + "\" }"));
        jwsObject.sign(signer);
        final String rawJwt = jwsObject.serialize();
        ((MockHttpServletRequest)action.getHttpServletRequest()).addParameter(jwtParameterName, rawJwt);
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }
    
    /**
     * Runs action without desired username in the incoming JWT.
     */
    @Test public void testMissingUsername() throws Exception {
        final JWSSigner signer = new MACSigner(sharedSecret);
        final JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), 
                new Payload("{ \"" + uidConfig + "invalid\" : \"" + uid + "\" }"));
        jwsObject.sign(signer);
        final String rawJwt = jwsObject.serialize();
        ((MockHttpServletRequest)action.getHttpServletRequest()).addParameter(jwtParameterName, rawJwt);
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with empty username in the incoming JWT.
     */
    @Test public void testEmptyUsername() throws Exception {
        final JWSSigner signer = new MACSigner(sharedSecret);
        final JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), 
                new Payload("{ \"" + uidConfig + "\" : \"\" }"));
        jwsObject.sign(signer);
        final String rawJwt = jwsObject.serialize();
        ((MockHttpServletRequest)action.getHttpServletRequest()).addParameter(jwtParameterName, rawJwt);
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with username string in the incoming JWT token.
     */
    @Test public void testSuccessString() throws Exception {
        final JWSSigner signer = new MACSigner(sharedSecret);
        final JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), 
                new Payload("{ \"" + uidConfig + "\" : \"" + uid + "\" }"));
        jwsObject.sign(signer);
        final String rawJwt = jwsObject.serialize();
        ((MockHttpServletRequest)action.getHttpServletRequest()).addParameter(jwtParameterName, rawJwt);
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        action.initialize();
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final AuthenticationContext authnCtx = prc.getSubcontext(AuthenticationContext.class);
        final AuthenticationResult authnResult = authnCtx.getAuthenticationResult();
        Assert.assertNotNull(authnResult.getSubject());
        final Set<Principal> principals = authnResult.getSubject().getPrincipals();
        Assert.assertNotNull(principals);
        Assert.assertEquals(1, principals.size());
        Assert.assertEquals(uid, principals.iterator().next().getName());
    }
    
    /**
     * Runs action with username number in the incoming JWT token.
     */
    @Test public void testSuccessNumber() throws Exception {
        final JWSSigner signer = new MACSigner(sharedSecret);
        final JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), 
                new Payload("{ \"" + uidConfig + "\" : " + uidNumber + " }"));
        jwsObject.sign(signer);
        final String rawJwt = jwsObject.serialize();
        ((MockHttpServletRequest)action.getHttpServletRequest()).addParameter(jwtParameterName, rawJwt);
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        action.initialize();
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final AuthenticationContext authnCtx = prc.getSubcontext(AuthenticationContext.class);
        final AuthenticationResult authnResult = authnCtx.getAuthenticationResult();
        Assert.assertNotNull(authnResult.getSubject());
        final Set<Principal> principals = authnResult.getSubject().getPrincipals();
        Assert.assertNotNull(principals);
        Assert.assertEquals(1, principals.size());
        Assert.assertEquals("" + uidNumber, principals.iterator().next().getName());
    }

}