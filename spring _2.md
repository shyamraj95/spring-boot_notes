To implement an admin interface for monitoring and managing blacklisted tokens, we’ll create REST endpoints that allow an admin to:

1. **View Blacklisted Tokens**:
   - Retrieve a list of all blacklisted tokens and their expiration timestamps.

2. **Manually Add Tokens to the Blacklist**:
   - Allow an admin to add a token to the blacklist manually (useful for invalidating specific tokens).

3. **Remove Tokens from the Blacklist**:
   - Allow an admin to remove tokens from the blacklist manually.

---

### Updated Implementation

---

#### 1. **AdminController**

Create an admin controller to expose endpoints for managing blacklisted tokens.

```java
package com.example.ldapauth.controller;

import com.example.ldapauth.service.SessionService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/admin/tokens")
public class AdminController {

    private final SessionService sessionService;

    public AdminController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    // Endpoint to view all blacklisted tokens
    @GetMapping("/blacklist")
    public Map<String, Long> viewBlacklistedTokens() {
        return sessionService.getAllBlacklistedTokens();
    }

    // Endpoint to manually blacklist a token
    @PostMapping("/blacklist")
    public String blacklistToken(@RequestParam String token, @RequestParam long expirationTimestamp) {
        sessionService.blacklistToken(token, expirationTimestamp);
        return "Token successfully blacklisted.";
    }

    // Endpoint to remove a token from the blacklist
    @DeleteMapping("/blacklist")
    public String removeBlacklistedToken(@RequestParam String token) {
        boolean removed = sessionService.removeTokenFromBlacklist(token);
        return removed ? "Token successfully removed from blacklist." : "Token not found in blacklist.";
    }
}
```

---

#### 2. **Update SessionService**

Add methods to support admin actions on the blacklist.

```java
package com.example.ldapauth.service;

import org.springframework.stereotype.Service;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SessionService {

    private final ConcurrentHashMap<String, String> activeSessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> blacklistedTokens = new ConcurrentHashMap<>();

    public void registerSession(String username, String refreshToken) {
        activeSessions.put(username, refreshToken);
    }

    public boolean isRefreshTokenValid(String username, String refreshToken) {
        cleanupExpiredTokens();
        return refreshToken.equals(activeSessions.get(username)) && !blacklistedTokens.containsKey(refreshToken);
    }

    public void invalidateSession(String username) {
        String token = activeSessions.remove(username);
        if (token != null) {
            blacklistToken(token, System.currentTimeMillis() + 15 * 60 * 1000); // Add 15 mins to simulate token lifespan
        }
    }

    public void blacklistToken(String token, long expirationTime) {
        blacklistedTokens.put(token, expirationTime);
    }

    public boolean isTokenBlacklisted(String token) {
        cleanupExpiredTokens();
        return blacklistedTokens.containsKey(token);
    }

    public Map<String, Long> getAllBlacklistedTokens() {
        cleanupExpiredTokens();
        return blacklistedTokens;
    }

    public boolean removeTokenFromBlacklist(String token) {
        cleanupExpiredTokens();
        return blacklistedTokens.remove(token) != null;
    }

    private void cleanupExpiredTokens() {
        long currentTime = System.currentTimeMillis();
        Iterator<Map.Entry<String, Long>> iterator = blacklistedTokens.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry<String, Long> entry = iterator.next();
            if (entry.getValue() < currentTime) {
                iterator.remove();
            }
        }
    }
}
```

---

#### 3. **Role-Based Access Control**

To ensure only admins can access these endpoints, update `SecurityConfig` to restrict access.

```java
package com.example.ldapauth.config;

import com.example.ldapauth.filter.JwtTokenFilter;
import com.example.ldapauth.service.DatabaseUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final DatabaseUserDetailsService databaseUserDetailsService;
    private final JwtTokenFilter jwtTokenFilter;

    public SecurityConfig(DatabaseUserDetailsService databaseUserDetailsService, JwtTokenFilter jwtTokenFilter) {
        this.databaseUserDetailsService = databaseUserDetailsService;
        this.jwtTokenFilter = jwtTokenFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(databaseUserDetailsService)
                .passwordEncoder(passwordEncoder());
        return auth.build();
    }

    @Bean
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/auth/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN") // Restrict admin endpoints
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
```

---

### Example API Usage

#### View Blacklisted Tokens

**Request**:
```http
GET /admin/tokens/blacklist
Authorization: Bearer <ADMIN_TOKEN>
```

**Response**:
```json
{
  "eyJhbGciOiJIUzI1NiJ9...": 1674439200000,
  "eyJhbGciOiJIUzI1NiJ0...": 1674442800000
}
```

#### Manually Blacklist a Token

**Request**:
```http
POST /admin/tokens/blacklist
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOiJIUzI1NiJ9...&expirationTimestamp=1674446400000
```

**Response**:
```json
{
  "message": "Token successfully blacklisted."
}
```

#### Remove a Token from the Blacklist

**Request**:
```http
DELETE /admin/tokens/blacklist
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOiJIUzI1NiJ9...
```

**Response**:
```json
{
  "message": "Token successfully removed from blacklist."
}
```

---

### Key Features of Admin Interface

1. **View Blacklisted Tokens**:
   - List all blacklisted tokens and their expiration timestamps.

2. **Manual Blacklist**:
   - Admins can manually invalidate a token by adding it to the blacklist.

3. **Manual Removal**:
   - Admins can remove tokens from the blacklist if needed.

4. **Secure Access**:
   - Only users with the `ADMIN` role can access these endpoints.

---

**a.** Would you like me to add Swagger for better API documentation?  
**b.** Should I add unit tests for the admin controller?



/////////////////////////////////////////




To add cleanup logic for expired tokens in the blacklist, we can periodically remove expired tokens using a background task or during validation checks. This approach ensures that the blacklist remains lightweight and doesn't grow indefinitely.

---

### Updated Plan for Token Cleanup

1. **Update `SessionService`**:
   - Store blacklisted tokens along with their expiration timestamps.
   - Implement a method to remove expired tokens.

2. **Cleanup During Validation**:
   - Perform cleanup when checking if a token is blacklisted.

3. **Background Cleanup Task (Optional)**:
   - Use a scheduled task to periodically clean expired tokens from the blacklist.

---

### Implementation

---

#### 1. **Update SessionService**

Modify the blacklist storage to include expiration timestamps.

```java
package com.example.ldapauth.service;

import org.springframework.stereotype.Service;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SessionService {

    private final ConcurrentHashMap<String, String> activeSessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> blacklistedTokens = new ConcurrentHashMap<>();

    public void registerSession(String username, String refreshToken) {
        activeSessions.put(username, refreshToken);
    }

    public boolean isRefreshTokenValid(String username, String refreshToken) {
        cleanupExpiredTokens();
        return refreshToken.equals(activeSessions.get(username)) && !blacklistedTokens.containsKey(refreshToken);
    }

    public void invalidateSession(String username) {
        String token = activeSessions.remove(username);
        if (token != null) {
            blacklistToken(token, System.currentTimeMillis() + 15 * 60 * 1000); // Add 15 mins to simulate token lifespan
        }
    }

    public void blacklistToken(String token, long expirationTime) {
        blacklistedTokens.put(token, expirationTime);
    }

    public boolean isTokenBlacklisted(String token) {
        cleanupExpiredTokens();
        return blacklistedTokens.containsKey(token);
    }

    // Remove expired tokens from the blacklist
    private void cleanupExpiredTokens() {
        long currentTime = System.currentTimeMillis();
        Iterator<Map.Entry<String, Long>> iterator = blacklistedTokens.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry<String, Long> entry = iterator.next();
            if (entry.getValue() < currentTime) {
                iterator.remove();
            }
        }
    }
}
```

---

#### 2. **JwtTokenFilter**

Modify the filter to ensure expired tokens are automatically removed from the blacklist.

```java
@Component
public class JwtTokenFilter extends org.springframework.web.filter.OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final SessionService sessionService;

    public JwtTokenFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService, SessionService sessionService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.sessionService = sessionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = jwtUtil.validateToken(token);
            if (jwtUtil.isTokenExpired(token) || sessionService.isTokenBlacklisted(token)) {
                throw new SecurityException("Token is invalid or expired");
            }

            String username = claims.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }
}
```

---

#### 3. **Optional: Background Cleanup Task**

For larger systems, you can periodically clean up expired tokens using a scheduled task.

```java
package com.example.ldapauth.task;

import com.example.ldapauth.service.SessionService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class TokenCleanupTask {

    private final SessionService sessionService;

    public TokenCleanupTask(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @Scheduled(fixedRate = 3600000) // Run every hour
    public void cleanupBlacklistedTokens() {
        sessionService.cleanupExpiredTokens();
    }
}
```

---

#### 4. **Add Configuration for Scheduling**

Enable scheduling in the Spring Boot application.

```java
package com.example.ldapauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class LdapAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(LdapAuthApplication.class, args);
    }
}
```

---

### Key Features of Cleanup Logic

1. **On-Demand Cleanup**:
   - `SessionService` automatically removes expired tokens during validation checks.

2. **Background Cleanup**:
   - An optional scheduled task periodically removes expired tokens to keep the blacklist lightweight.

3. **Seamless Integration**:
   - The system validates token expiration and blacklist status without impacting user experience.

---

**a.** Would you like unit tests for the cleanup logic?  
**b.** Should we implement an admin interface to monitor and manage blacklisted tokens?




//////////////////////////



Here’s the implementation of token expiration and refresh mechanisms in a Spring Boot application using Spring Security and JWT.

---

### Implementation Steps

1. **Token Expiration**:
   - Include an expiration time in the JWT token payload.
   - Validate the expiration during token parsing.

2. **Refresh Token Endpoint**:
   - Add an endpoint to refresh tokens.
   - Issue a new token if the refresh token is valid and unexpired.

3. **Token Management**:
   - Use a `SessionService` to track active sessions and ensure a single session per user.

---

### Updated Code

#### 1. **JwtUtil**: Token Generation, Validation, and Refresh

```java
package com.example.ldapauth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 1000 * 60 * 15; // 15 minutes
    private static final long REFRESH_EXPIRATION_TIME = 1000 * 60 * 60 * 24; // 24 hours

    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
    }

    public String generateRefreshToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
    }

    public Claims validateToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenExpired(String token) {
        Date expiration = validateToken(token).getExpiration();
        return expiration.before(new Date());
    }

    public String refreshAccessToken(String username, String role) {
        return generateToken(username, role);
    }
}
```

---

#### 2. **SessionService**: Manage Active Sessions

```java
package com.example.ldapauth.service;

import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

@Service
public class SessionService {

    private final ConcurrentHashMap<String, String> activeSessions = new ConcurrentHashMap<>();

    public void registerSession(String username, String refreshToken) {
        activeSessions.put(username, refreshToken);
    }

    public boolean isRefreshTokenValid(String username, String refreshToken) {
        return refreshToken.equals(activeSessions.get(username));
    }

    public void invalidateSession(String username) {
        activeSessions.remove(username);
    }
}
```

---

#### 3. **LoginController**: Token Issuance and Refresh

```java
package com.example.ldapauth.controller;

import com.example.ldapauth.entity.User;
import com.example.ldapauth.repository.UserRepository;
import com.example.ldapauth.service.AuditService;
import com.example.ldapauth.service.SessionService;
import com.example.ldapauth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final JwtUtil jwtUtil;
    private final SessionService sessionService;

    @Autowired
    public LoginController(AuthenticationManager authenticationManager,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           AuditService auditService,
                           JwtUtil jwtUtil,
                           SessionService sessionService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
        this.jwtUtil = jwtUtil;
        this.sessionService = sessionService;
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password, HttpServletRequest request) {
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (!userOptional.isPresent()) {
            auditService.log(username, false, "User not found in database", request.getRemoteAddr());
            throw new BadCredentialsException("User not found");
        }

        User user = userOptional.get();
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            auditService.log(username, true, "LDAP Authentication successful", request.getRemoteAddr());
        } catch (Exception ldapEx) {
            if (!passwordEncoder.matches(password, user.getPassword())) {
                auditService.log(username, false, "Invalid credentials", request.getRemoteAddr());
                throw new BadCredentialsException("Invalid credentials");
            }
            auditService.log(username, true, "Fallback to DB Authentication successful", request.getRemoteAddr());
        }

        // Generate tokens
        String accessToken = jwtUtil.generateToken(user.getUsername(), user.getRole());
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

        // Register session
        sessionService.registerSession(user.getUsername(), refreshToken);

        return "Login successful. Access Token: " + accessToken + ", Refresh Token: " + refreshToken;
    }

    @PostMapping("/refresh-token")
    public String refreshToken(@RequestParam String refreshToken) {
        Claims claims = jwtUtil.validateToken(refreshToken);
        String username = claims.getSubject();

        if (!sessionService.isRefreshTokenValid(username, refreshToken)) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        // Generate a new access token
        String newAccessToken = jwtUtil.refreshAccessToken(username, claims.get("role", String.class));
        return "New Access Token: " + newAccessToken;
    }
}
```

---

#### 4. **JwtTokenFilter**: Validate Token Expiration

```java
package com.example.ldapauth.filter;

import com.example.ldapauth.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtTokenFilter extends org.springframework.web.filter.OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    public JwtTokenFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = jwtUtil.validateToken(token);
            if (jwtUtil.isTokenExpired(token)) {
                throw new SecurityException("Token is expired");
            }

            String username = claims.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }
}
```

---

### Key Features

1. **Token Expiration**:
   - Access tokens expire after 15 minutes.
   - Refresh tokens expire after 24 hours.

2. **Refresh Tokens**:
   - A refresh endpoint issues a new access token using the refresh token.

3. **Single Session**:
   - Enforce single-session behavior via the `SessionService`.

---

**a.** Would you like to add tests for token refresh and expiration?  
**b.** Should I include token blacklist for immediate logout functionality?



///////////////////////




You're absolutely right: storing the IP in the token and also maintaining it in the audit table is redundant. A better approach is to validate the client IP dynamically by checking it against the audit table or the session-tracking mechanism. This keeps the token lightweight and avoids redundancy. I'll also implement token expiration and refresh mechanisms for better security.

---

### Revised Plan

1. **Remove IP Address from Token**:
   - Store and validate the IP address only in the audit table and session tracking service.

2. **Token Expiration**:
   - Use an expiration time for tokens in the JWT payload.

3. **Token Refresh**:
   - Introduce an endpoint for token refresh, which validates the existing token and issues a new one with an updated expiration.

4. **Single Session Validation**:
   - Continue enforcing single-session tokens per user using the session service.

---

### Implementation

---

#### 1. **JwtUtil**

Add expiration validation and methods for refreshing tokens.

```java
package com.example.ldapauth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 1000 * 60 * 15; // 15 minutes
    private static final long REFRESH_EXPIRATION_TIME = 1000 * 60 * 60 * 24; // 24 hours

    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
    }

    public Claims validateToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenExpired(String token) {
        Date expiration = validateToken(token).getExpiration();
        return expiration.before(new Date());
    }

    public String refreshToken(String token) {
        Claims claims = validateToken(token);
        return Jwts.builder()
                .setSubject(claims.getSubject())
                .claim("role", claims.get("role"))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
    }
}
```

---

#### 2. **SessionService**

Ensure single-session enforcement.

```java
package com.example.ldapauth.service;

import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

@Service
public class SessionService {

    private final ConcurrentHashMap<String, String> activeSessions = new ConcurrentHashMap<>();

    public void registerToken(String username, String token) {
        activeSessions.put(username, token);
    }

    public boolean isTokenValid(String username, String token) {
        return token.equals(activeSessions.get(username));
    }

    public void invalidateToken(String username) {
        activeSessions.remove(username);
    }
}
```

---

#### 3. **LoginController**

Update the controller to handle session tracking and token refresh.

```java
package com.example.ldapauth.controller;

import com.example.ldapauth.entity.User;
import com.example.ldapauth.repository.UserRepository;
import com.example.ldapauth.service.AuditService;
import com.example.ldapauth.service.SessionService;
import com.example.ldapauth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final JwtUtil jwtUtil;
    private final SessionService sessionService;

    @Autowired
    public LoginController(AuthenticationManager authenticationManager,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           AuditService auditService,
                           JwtUtil jwtUtil,
                           SessionService sessionService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
        this.jwtUtil = jwtUtil;
        this.sessionService = sessionService;
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password, HttpServletRequest request) {
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (!userOptional.isPresent()) {
            auditService.log(username, false, "User not found in database", request.getRemoteAddr());
            throw new BadCredentialsException("User not found");
        }

        User user = userOptional.get();
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            auditService.log(username, true, "LDAP Authentication successful", request.getRemoteAddr());
        } catch (AuthenticationException ldapEx) {
            if (!passwordEncoder.matches(password, user.getPassword())) {
                auditService.log(username, false, "Invalid credentials", request.getRemoteAddr());
                throw new BadCredentialsException("Invalid credentials");
            }
            auditService.log(username, true, "Fallback to DB Authentication successful", request.getRemoteAddr());
        }

        // Generate new token and register session
        String jwtToken = jwtUtil.generateToken(user.getUsername(), user.getRole());
        sessionService.registerToken(user.getUsername(), jwtToken);

        return "Login successful. Token: " + jwtToken;
    }

    @PostMapping("/refresh-token")
    public String refreshToken(@RequestParam String token) {
        if (jwtUtil.isTokenExpired(token)) {
            throw new BadCredentialsException("Token is expired");
        }

        String username = jwtUtil.validateToken(token).getSubject();
        String newToken = jwtUtil.refreshToken(token);

        // Update session with the new token
        sessionService.registerToken(username, newToken);

        return "Token refreshed successfully. New Token: " + newToken;
    }
}
```

---

#### 4. **JwtTokenFilter**

Validate token expiration and session status.

```java
package com.example.ldapauth.filter;

import com.example.ldapauth.service.SessionService;
import com.example.ldapauth.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtTokenFilter extends org.springframework.web.filter.OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final SessionService sessionService;

    public JwtTokenFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService, SessionService sessionService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.sessionService = sessionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = jwtUtil.validateToken(token);
            String username = claims.getSubject();

            if (!sessionService.isTokenValid(username, token)) {
                throw new SecurityException("Token invalid due to another active session");
            }

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }
}
```

---

### Key Features

1. **Single Session**: Only one active token per user.
2. **Token Expiration**: Tokens expire after 15 minutes, with refresh tokens valid for 24 hours.
3. **Token Refresh**: Users can refresh tokens before expiration.

---

**a.** Would you like to log refresh attempts in the audit table?  
**b.** Should I include test cases for token expiration and refresh?




//////////////////////////




To implement the requested functionality:

1. **Audit Client IP Address**: Capture the client IP address during authentication and store it in the audit table.
2. **Token IP Address Validation**: Include the client IP address in the JWT token payload. During token validation, check if the IP address matches.
3. **Single Session Enforcement**: Maintain a record of the active session for each user (e.g., using a database or in-memory storage) and invalidate any previously issued tokens for the user when a new token is generated.

---

### Implementation Steps

---

#### 1. **Enhance Audit Entity**

Add a field to store the client IP address.

```java
package com.example.ldapauth.entity;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
public class Audit {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private boolean success;

    private String reason;

    private LocalDateTime timestamp;

    private String ipAddress; // Add IP address field

    // Getters and setters
}
```

---

#### 2. **Enhance `JwtUtil` to Include IP Address**

Modify the JWT generation and validation to include and verify the IP address.

```java
package com.example.ldapauth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 10; // 10 hours

    public String generateToken(String username, String role, String ipAddress) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .claim("ipAddress", ipAddress) // Include IP address
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
    }

    public Claims validateToken(String token, String requestIpAddress) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // Validate IP address
        String tokenIpAddress = claims.get("ipAddress", String.class);
        if (!requestIpAddress.equals(tokenIpAddress)) {
            throw new SecurityException("Invalid IP address");
        }

        return claims;
    }
}
```

---

#### 3. **Track Active Sessions**

Maintain a mapping of active tokens in a service to enforce a single session per user.

```java
package com.example.ldapauth.service;

import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

@Service
public class SessionService {

    private final ConcurrentHashMap<String, String> activeSessions = new ConcurrentHashMap<>();

    public void registerToken(String username, String token) {
        activeSessions.put(username, token);
    }

    public boolean isTokenValid(String username, String token) {
        return token.equals(activeSessions.get(username));
    }

    public void invalidateToken(String username) {
        activeSessions.remove(username);
    }
}
```

---

#### 4. **Enhance LoginController**

Incorporate client IP address and session handling in login logic.

```java
package com.example.ldapauth.controller;

import com.example.ldapauth.entity.User;
import com.example.ldapauth.repository.UserRepository;
import com.example.ldapauth.service.AuditService;
import com.example.ldapauth.service.SessionService;
import com.example.ldapauth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final JwtUtil jwtUtil;
    private final SessionService sessionService;

    @Autowired
    public LoginController(AuthenticationManager authenticationManager,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           AuditService auditService,
                           JwtUtil jwtUtil,
                           SessionService sessionService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
        this.jwtUtil = jwtUtil;
        this.sessionService = sessionService;
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password, HttpServletRequest request) {
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (!userOptional.isPresent()) {
            auditService.log(username, false, "User not found in database", request.getRemoteAddr());
            throw new BadCredentialsException("User not found");
        }

        User user = userOptional.get();
        try {
            // Attempt LDAP authentication
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            auditService.log(username, true, "LDAP Authentication successful", request.getRemoteAddr());
        } catch (AuthenticationException ldapEx) {
            // Fallback to database authentication
            if (!passwordEncoder.matches(password, user.getPassword())) {
                auditService.log(username, false, "Invalid credentials", request.getRemoteAddr());
                throw new BadCredentialsException("Invalid credentials");
            }
            auditService.log(username, true, "Fallback to DB Authentication successful", request.getRemoteAddr());
        }

        // Generate JWT token
        String clientIp = request.getRemoteAddr();
        String jwtToken = jwtUtil.generateToken(user.getUsername(), user.getRole(), clientIp);

        // Register session
        sessionService.registerToken(user.getUsername(), jwtToken);

        return "Login successful. Token: " + jwtToken;
    }
}
```

---

#### 5. **Enhance JwtTokenFilter**

Validate IP address and enforce single session.

```java
package com.example.ldapauth.filter;

import com.example.ldapauth.service.SessionService;
import com.example.ldapauth.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtTokenFilter extends org.springframework.web.filter.OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final SessionService sessionService;

    public JwtTokenFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService, SessionService sessionService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.sessionService = sessionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7); // Remove "Bearer " prefix
        String clientIp = request.getRemoteAddr();

        try {
            Claims claims = jwtUtil.validateToken(token, clientIp);
            String username = claims.getSubject();

            // Enforce single session
            if (!sessionService.isTokenValid(username, token)) {
                throw new SecurityException("Token invalid due to another active session");
            }

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }
}
```

---

### Summary of Features

1. **Audit Table**: Logs the client IP address during login.
2. **IP Address Validation**: JWT tokens include the IP address and validate it on every request.
3. **Single Session**: Ensures only one active token per user.

---

**a.** Would you like test cases for these updates?  
**b.** Should I implement token expiration and refresh mechanisms?



//////////////////////////



You're absolutely right! Adding a `JwtTokenFilter` is essential for securing the application by validating JWT tokens for protected endpoints. The `JwtTokenFilter` will ensure that only authenticated users with valid tokens can access secured resources.

Here's the complete implementation, including the `JwtTokenFilter`, to handle JWT-based security.

---

### Implementation with `JwtTokenFilter`

---

#### 1. **JwtTokenFilter**

The filter will:
- Extract the JWT token from the `Authorization` header.
- Validate the token and set the `SecurityContext` if valid.

```java
package com.example.ldapauth.filter;

import com.example.ldapauth.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtTokenFilter extends org.springframework.web.filter.OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    public JwtTokenFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // Extract token from the Authorization header
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7); // Remove "Bearer " prefix

        try {
            // Validate token and extract claims
            Claims claims = jwtUtil.validateToken(token);
            String username = claims.getSubject();
            String role = claims.get("role", String.class);

            // Load user details
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Set authentication in the context
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            // Clear context if token is invalid
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }
}
```

---

#### 2. **Integrate JwtTokenFilter into SecurityConfig**

Update the `SecurityConfig` to include the `JwtTokenFilter` in the filter chain.

```java
package com.example.ldapauth.config;

import com.example.ldapauth.filter.JwtTokenFilter;
import com.example.ldapauth.service.DatabaseUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final DatabaseUserDetailsService databaseUserDetailsService;
    private final JwtTokenFilter jwtTokenFilter;

    public SecurityConfig(DatabaseUserDetailsService databaseUserDetailsService, JwtTokenFilter jwtTokenFilter) {
        this.databaseUserDetailsService = databaseUserDetailsService;
        this.jwtTokenFilter = jwtTokenFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(databaseUserDetailsService)
                .passwordEncoder(passwordEncoder());
        return auth.build();
    }

    @Bean
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/auth/**").permitAll() // Public endpoints
                .anyRequest().authenticated()       // Secure all other endpoints
                .and()
                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class); // Add JWT filter
    }
}
```

---

#### 3. **Update JwtUtil**

The `JwtUtil` class now includes a method to extract and validate claims:

```java
package com.example.ldapauth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 10; // 10 hours

    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
    }

    public Claims validateToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
```

---

### Workflow After Adding JwtTokenFilter

1. **Login**:
   - User logs in via `/auth/login`.
   - A valid JWT token is issued on successful authentication.

2. **Access Protected Endpoints**:
   - Client includes the JWT token in the `Authorization` header of requests:  
     `Authorization: Bearer <JWT_TOKEN>`.
   - The `JwtTokenFilter` validates the token and sets the authentication in the `SecurityContext`.

3. **SecurityContext**:
   - The user's role and authentication status are derived from the JWT token.

---

### Example Requests

#### Login Request

**Request**:
```json
POST /auth/login
{
  "username": "john",
  "password": "password123"
}
```

**Response**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

#### Protected Endpoint Access

**Request**:
```http
GET /api/secure-resource
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

**Response**:
```json
{
  "message": "Access granted"
}
```

---

### Advantages of Adding JwtTokenFilter

1. **Decoupled Security**:
   - Authorization is handled separately via the token, reducing dependency on server state.

2. **Stateless Authentication**:
   - JWT tokens eliminate the need for server-side session storage.

3. **Scalability**:
   - Stateless JWT authentication scales better in distributed environments.

---

**a.** Would you like to add custom exception handling for the `JwtTokenFilter`?  
**b.** Should I include unit tests for the filter?



///////////////////////////



Here's an updated implementation of the `LoginController` and supporting configurations to ensure the following:

1. **LDAP Authentication**: Attempt LDAP authentication only if the user exists in the database.
2. **JWT Token**: Include role details in the JWT token.

---

### Updated Plan

1. **Enhance the `LoginController`**:
   - Check if the user exists in the database before attempting LDAP authentication.
   - Generate a JWT token upon successful login (LDAP or database).

2. **JWT Utility**:
   - Create a utility class for generating and validating JWT tokens.
   - Include the user's role in the token payload.

3. **Enhance Security Configuration**:
   - Add support for JWT-based authentication.

4. **Response Updates**:
   - Return a JWT token along with success messages after authentication.

---

### Implementation

#### 1. **JWT Utility**

```java
package com.example.ldapauth.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtil {

    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 10; // 10 hours

    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
    }

    public Map<String, Object> validateToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
```

---

#### 2. **LoginController**

```java
package com.example.ldapauth.controller;

import com.example.ldapauth.entity.User;
import com.example.ldapauth.repository.UserRepository;
import com.example.ldapauth.service.AuditService;
import com.example.ldapauth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final JwtUtil jwtUtil;

    @Autowired
    public LoginController(AuthenticationManager authenticationManager,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           AuditService auditService,
                           JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (!userOptional.isPresent()) {
            auditService.log(username, false, "User not found in database");
            throw new BadCredentialsException("User not found");
        }

        User user = userOptional.get();
        try {
            // Attempt LDAP authentication if the user exists in the database
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            auditService.log(username, true, "LDAP Authentication successful");
        } catch (AuthenticationException ldapEx) {
            // Fallback to database authentication
            if (!passwordEncoder.matches(password, user.getPassword())) {
                auditService.log(username, false, "Invalid credentials");
                throw new BadCredentialsException("Invalid credentials");
            }
            auditService.log(username, true, "Fallback to DB Authentication successful");
        }

        // Generate JWT token including role
        String jwtToken = jwtUtil.generateToken(user.getUsername(), user.getRole());
        return "Login successful. Token: " + jwtToken;
    }

    @PostMapping("/signup")
    public String signup(@RequestParam String username, @RequestParam String password, @RequestParam String role) {
        if (userRepository.findByUsername(username).isPresent()) {
            return "User already exists!";
        }
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role);
        userRepository.save(user);
        return "User registered successfully!";
    }
}
```

---

#### 3. **Security Configuration**

Update the `SecurityConfig` to add JWT authentication.

```java
package com.example.ldapauth.config;

import com.example.ldapauth.service.DatabaseUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig {

    private final DatabaseUserDetailsService databaseUserDetailsService;

    public SecurityConfig(DatabaseUserDetailsService databaseUserDetailsService) {
        this.databaseUserDetailsService = databaseUserDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(databaseUserDetailsService)
                .passwordEncoder(passwordEncoder());
        return auth.build();
    }

    @Bean
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/auth/**").permitAll()
                .anyRequest().authenticated();
    }
}
```

---

### Sample Requests and JWT Workflow

#### Login Request
**URL**: `POST /auth/login`  
**Body**:
```json
{
  "username": "john",
  "password": "password123"
}
```
**Response**:
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

#### Validate JWT Token
Decode the token using a JWT decoder (e.g., [jwt.io](https://jwt.io)). It will contain the role as:
```json
{
  "sub": "john",
  "role": "USER",
  "iat": 1673870197,
  "exp": 1673913397
}
```

---

**a.** Would you like me to add middleware to validate JWT tokens in all requests?  
**b.** Should I include unit tests for the JWT utility and `LoginController`?