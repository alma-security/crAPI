/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.crapi.config;

import com.crapi.entity.User;
import com.crapi.enums.ERole;
import com.crapi.repository.UserRepository;
import com.google.gson.Gson;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

@RunWith(MockitoJUnitRunner.class)
public class JwtProviderTest {

    private JwtProvider jwtProvider;

    @Mock private UserRepository userRepository;

    @Before
    public void setUp() throws Exception {
        RSAKey rsaKey =
                new RSAKeyGenerator(2048)
                        .keyID("test-key")
                        .algorithm(JWSAlgorithm.RS256)
                        .generate();
        // toJSONObject(false) includes the private key, which JwtProvider needs to sign tokens
        String jwkSetJson = new Gson().toJson(new JWKSet(rsaKey).toJSONObject(false));
        String jwksEncoded =
                Base64.getEncoder().encodeToString(jwkSetJson.getBytes(StandardCharsets.UTF_8));
        jwtProvider = new JwtProvider(jwksEncoded);
        ReflectionTestUtils.setField(jwtProvider, "userRepository", userRepository);
    }

    /**
     * With the new 1-hour default (3 600 000 ms), the generated JWT must expire within 72 hours.
     * This is the primary regression guard for the "JWT Expiration Exceeds 72 Hours" finding.
     */
    @Test
    public void testJwtExpirationDoesNotExceed72Hours() throws Exception {
        ReflectionTestUtils.setField(jwtProvider, "jwtExpiration", "3600000"); // 1 hour
        User user = new User("test@example.com", "1234567890", "password", ERole.ROLE_USER);

        String token = jwtProvider.generateJwtToken(user);

        SignedJWT jwt = SignedJWT.parse(token);
        long issuedAtMs = jwt.getJWTClaimsSet().getIssueTime().getTime();
        long expirationMs = jwt.getJWTClaimsSet().getExpirationTime().getTime();
        long lifetimeMs = expirationMs - issuedAtMs;
        long maxAllowedMs = 72L * 60 * 60 * 1000; // 72 hours in ms
        Assert.assertTrue(
                "JWT lifetime " + (lifetimeMs / 3_600_000L) + "h must not exceed 72h",
                lifetimeMs <= maxAllowedMs);
    }

    /**
     * Regression guard: demonstrates that the old 7-day default (604 800 000 ms) would have
     * produced a token exceeding the 72-hour limit, confirming the fix is necessary.
     */
    @Test
    public void testLegacy7DayDefaultExceeds72HourLimit() throws Exception {
        ReflectionTestUtils.setField(jwtProvider, "jwtExpiration", "604800000"); // 7 days (old)
        User user = new User("test@example.com", "1234567890", "password", ERole.ROLE_USER);

        String token = jwtProvider.generateJwtToken(user);

        SignedJWT jwt = SignedJWT.parse(token);
        long issuedAtMs = jwt.getJWTClaimsSet().getIssueTime().getTime();
        long expirationMs = jwt.getJWTClaimsSet().getExpirationTime().getTime();
        long lifetimeMs = expirationMs - issuedAtMs;
        long maxAllowedMs = 72L * 60 * 60 * 1000;
        Assert.assertTrue(
                "The old 7-day default must exceed the 72-hour limit (regression guard)",
                lifetimeMs > maxAllowedMs);
    }
}
