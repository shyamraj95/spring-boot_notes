Let’s break this down step-by-step to explain where the role is mentioned and how it’s applied in the code:

1. Role Specification in the Code

a. .requestMatchers("/admin/**").hasRole("ADMIN")

This is part of the Spring Security Configuration in the SecurityConfig class. It secures all endpoints under /admin/**, allowing access only to users who have the ROLE_ADMIN role.

b. @PreAuthorize("hasRole('USER')")

This is an annotation applied at the method level in your controller. It ensures that only users with the ROLE_USER role can access the specific method.

2. Where Are the Roles Specified?

The roles are typically stored in the database as part of the user information. For example:

User Entity

In the User entity class, there is a roles field that stores the roles assigned to the user, such as ROLE_ADMIN or ROLE_USER.

@Data
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    private String roles; // Example: "ROLE_USER,ROLE_ADMIN"
}

	•	During login, roles from this field are included in the JWT token:

String roles = existingUser.get().getRoles(); // Example: "ROLE_USER,ROLE_ADMIN"
String jwtToken = jwtUtil.generateToken(user.getUsername(), roles);

3. How Are Roles Applied in Security?

a. Role Prefix in Spring Security

Spring Security expects roles to have a ROLE_ prefix by default. For example:
	•	hasRole("ADMIN") will internally check for ROLE_ADMIN.
	•	hasRole("USER") will internally check for ROLE_USER.

This behavior is consistent across both .requestMatchers() in the SecurityConfig class and @PreAuthorize.

b. Roles in JWT Token

The roles are extracted from the JWT token during authentication and stored in the SecurityContext.

// JwtTokenFilter: Setting roles in SecurityContext
UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
    username,
    null,
    Arrays.stream(roles.split(","))
          .map(SimpleGrantedAuthority::new) // Convert roles to SimpleGrantedAuthority
          .collect(Collectors.toList())
);
SecurityContextHolder.getContext().setAuthentication(authenticationToken);

Here:
	•	roles from the token is parsed and converted to SimpleGrantedAuthority objects.
	•	SimpleGrantedAuthority internally prefixes the roles with ROLE_.

4. Role Matching

When a request is made:
	1.	Spring Security checks the SecurityContext for the authenticated user’s roles.
	2.	If .requestMatchers("/admin/**").hasRole("ADMIN") is configured, Spring verifies whether the user has ROLE_ADMIN in their list of authorities.
	3.	Similarly, for @PreAuthorize("hasRole('USER')"), Spring verifies whether the user has ROLE_USER.

5. Where Roles Are Set for Users

Roles are set in the following places:
	1.	Database: Roles (ROLE_ADMIN, ROLE_USER, etc.) are stored in the user’s record.
	2.	JWT Token: Roles are embedded in the JWT token during login.
	3.	SecurityContext: During authentication, roles from the JWT token are parsed and added to the SecurityContext.

Example Flow
	1.	User Data in Database:

{
    "username": "admin",
    "password": "hashed_password",
    "roles": "ROLE_ADMIN,ROLE_USER"
}


	2.	Login and JWT Token Creation:
	•	During login, roles are extracted from the database and embedded in the JWT:

String roles = "ROLE_ADMIN,ROLE_USER"; // From database
String jwtToken = jwtUtil.generateToken(username, roles);


	3.	JWT Validation:
	•	When a request is made, the roles are extracted from the JWT:

String roles = jwtUtil.extractRoles(token); // "ROLE_ADMIN,ROLE_USER"


	4.	Role Checking:
	•	If the user accesses /admin/**, Spring Security checks whether ROLE_ADMIN is in the user’s roles.
	•	If the user calls a controller method annotated with @PreAuthorize("hasRole('USER')"), Spring verifies whether ROLE_USER is in the user’s roles.

Summary
	1.	Roles Are Mentioned in the Database: Stored in the roles field of the user record as ROLE_USER, ROLE_ADMIN, etc.
	2.	Roles Are Embedded in JWT: Included in the token during login.
	3.	Roles Are Used in Security Context: Parsed from the JWT and set as authorities in the SecurityContext.
	4.	Spring Security Checks the Roles: Validates roles using .requestMatchers() or @PreAuthorize.

Let me know if you’d like to see an example of embedding roles in the JWT or querying roles from a database!



////////////////////////////


Here’s how to secure endpoints with role-based access control using Spring Security in a Spring Boot 2.7 application. We’ll modify the existing configuration to enforce role-based restrictions, ensuring that only authorized users can access specific endpoints based on their roles.

Steps to Secure Endpoints
	1.	Update Roles in User Entity: Ensure that the roles field in the User entity contains proper role definitions, e.g., ROLE_USER, ROLE_ADMIN.
	2.	Add Role-based Authorization Rules: Use Spring Security’s @PreAuthorize or HttpSecurity configuration to restrict access.
	3.	Implement Role Handling in JWT: Parse and validate roles from JWT tokens and set them in the SecurityContext.

Implementation

1. Update Security Configuration

Add role-based access control using HttpSecurity in the SecurityConfig class.

package com.example.security.config;

import com.example.security.jwt.JwtTokenFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final JwtTokenFilter jwtTokenFilter;

    public SecurityConfig(JwtTokenFilter jwtTokenFilter) {
        this.jwtTokenFilter = jwtTokenFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests()
                .requestMatchers("/auth/register", "/auth/login", "/auth/refresh").permitAll() // Open endpoints
                .requestMatchers("/admin/**").hasRole("ADMIN") // Only ADMIN can access /admin/**
                .requestMatchers("/user/**").hasRole("USER")   // Only USER can access /user/**
                .anyRequest().authenticated(); // All other requests require authentication

        // Add JWT filter
        http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);

        // Clear security context after request
        http.addFilterAfter((request, response, chain) -> {
            chain.doFilter(request, response);
            SecurityContextHolder.clearContext();
        }, JwtTokenFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}

2. Update JWT Authentication Token

Ensure the roles in the JWT token are added to the SecurityContext during authentication. Update the JwtTokenFilter to include roles:

package com.example.security.jwt;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtTokenFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwtToken = authHeader.substring(7);

            if (jwtUtil.validateToken(jwtToken)) {
                String username = jwtUtil.extractUsername(jwtToken);
                String roles = jwtUtil.extractRoles(jwtToken);

                // Parse roles and set authentication context
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        Arrays.stream(roles.split(","))
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList())
                );

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}

3. Controller Role-Based Restrictions

Use @PreAuthorize or @Secured annotations to secure specific controller methods.

package com.example.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class SecuredController {

    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminDashboard() {
        return "Welcome to the Admin Dashboard";
    }

    @GetMapping("/user/profile")
    @PreAuthorize("hasRole('USER')")
    public String userProfile() {
        return "Welcome to the User Profile";
    }

    @GetMapping("/common")
    public String commonEndpoint() {
        return "This endpoint is accessible to all authenticated users.";
    }
}

4. Add Roles to JWT Token During Login

Modify the login method in UserController to add roles to the JWT token.

@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody User user, HttpServletRequest request) {
    Optional<User> existingUser = userRepository.findByUsername(user.getUsername());
    if (!existingUser.isPresent() || !passwordEncoder.matches(user.getPassword(), existingUser.get().getPassword())) {
        return ResponseEntity.status(401).body("Invalid username or password.");
    }

    String roles = existingUser.get().getRoles(); // Example: "ROLE_USER,ROLE_ADMIN"
    String jwtToken = jwtUtil.generateToken(user.getUsername(), roles);

    // Store session details in the audit log
    AuditLog auditLog = new AuditLog();
    auditLog.setUsername(user.getUsername());
    auditLog.setIpAddress(request.getRemoteAddr());
    auditLog.setJwtToken(jwtToken);
    auditLog.setLoginTime(LocalDateTime.now());
    auditLog.setActive(true);
    auditLogRepository.save(auditLog);

    return ResponseEntity.ok().body(jwtToken);
}

How It Works
	1.	Endpoint Security: The HttpSecurity configuration ensures only users with the correct roles (ROLE_ADMIN, ROLE_USER) can access specific endpoints.
	2.	JWT Role Parsing: The JwtTokenFilter parses the roles from the token and sets them in the SecurityContext.
	3.	Method-Level Security: The @PreAuthorize annotation further restricts access to specific controller methods based on roles.

Testing the Implementation
	•	Register a user with ROLE_USER or ROLE_ADMIN.
	•	Test the endpoints:
	•	/admin/dashboard: Only accessible to users with ROLE_ADMIN.
	•	/user/profile: Only accessible to users with ROLE_USER.
	•	/common: Accessible to all authenticated users.

Next Steps

a. Add unit tests to verify endpoint security based on roles.
b. Integrate role-based permission checks for more granular authorization at the method level.




//////////////////////////////



Here is a Spring Boot 2.7 controller implementation for user creation, login, refreshing tokens, and logging out. It includes services for managing users, issuing JWT tokens, and handling logout.

Controller Code

This controller handles:
	1.	User Registration (POST /auth/register)
	2.	Login (POST /auth/login)
	3.	Token Refresh (POST /auth/refresh)
	4.	Logout (POST /auth/logout)

UserController.java

package com.example.security.controller;

import com.example.security.entity.AuditLog;
import com.example.security.entity.User;
import com.example.security.jwt.JwtUtil;
import com.example.security.repository.AuditLogRepository;
import com.example.security.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Register a new user.
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username already exists.");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return ResponseEntity.ok("User registered successfully.");
    }

    /**
     * Login with username and password to get a JWT token.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user, HttpServletRequest request) {
        Optional<User> existingUser = userRepository.findByUsername(user.getUsername());
        if (!existingUser.isPresent() || !passwordEncoder.matches(user.getPassword(), existingUser.get().getPassword())) {
            return ResponseEntity.status(401).body("Invalid username or password.");
        }

        String roles = existingUser.get().getRoles(); // User roles to embed in the token
        String jwtToken = jwtUtil.generateToken(user.getUsername(), roles);

        // Store session details in the audit log
        AuditLog auditLog = new AuditLog();
        auditLog.setUsername(user.getUsername());
        auditLog.setIpAddress(request.getRemoteAddr());
        auditLog.setJwtToken(jwtToken);
        auditLog.setLoginTime(LocalDateTime.now());
        auditLog.setActive(true);
        auditLogRepository.save(auditLog);

        return ResponseEntity.ok().body(jwtToken);
    }

    /**
     * Refresh JWT Token.
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String authHeader, HttpServletRequest request) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Invalid token.");
        }

        String oldToken = authHeader.substring(7);
        if (!jwtUtil.validateToken(oldToken)) {
            return ResponseEntity.status(401).body("Token is invalid or expired.");
        }

        String username = jwtUtil.extractUsername(oldToken);
        Optional<AuditLog> auditLog = auditLogRepository.findByUsernameAndIpAddressAndIsActive(username, request.getRemoteAddr(), true);

        if (!auditLog.isPresent() || !auditLog.get().getJwtToken().equals(oldToken)) {
            return ResponseEntity.status(401).body("Invalid session.");
        }

        String roles = jwtUtil.extractRoles(oldToken);
        String newToken = jwtUtil.generateToken(username, roles);

        // Update the audit log with the new token
        auditLog.get().setJwtToken(newToken);
        auditLogRepository.save(auditLog.get());

        return ResponseEntity.ok().body(newToken);
    }

    /**
     * Logout by deactivating the user's session.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader, HttpServletRequest request) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Invalid token.");
        }

        String token = authHeader.substring(7);
        String username = jwtUtil.extractUsername(token);

        Optional<AuditLog> auditLog = auditLogRepository.findByUsernameAndIpAddressAndIsActive(username, request.getRemoteAddr(), true);

        if (auditLog.isPresent()) {
            // Mark session as inactive
            AuditLog log = auditLog.get();
            log.setActive(false);
            log.setLogoutTime(LocalDateTime.now());
            auditLogRepository.save(log);
        }

        return ResponseEntity.ok("Logged out successfully.");
    }
}

Supporting Classes

User.java

User entity with roles.

package com.example.security.entity;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    private String roles; // E.g., ROLE_USER, ROLE_ADMIN
}

UserRepository.java

Repository for user data.

package com.example.security.repository;

import com.example.security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}

Configuration

SecurityConfig.java

To allow password encoding and basic security configuration.

package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

How It Works
	1.	Register: New users register with a username, password, and roles.
	2.	Login: Users provide their credentials to receive a JWT token. The session is tracked in the audit log with the client’s IP.
	3.	Refresh: Refresh tokens are generated after validating the active session and IP.
	4.	Logout: Deactivates the user’s session in the audit log.

Next Steps

a. Add unit tests for each endpoint to ensure functionality.
b. Secure endpoints with role-based access control using Spring Security.


////////////////////////////////////////////////////


Below is an implementation of Spring Security session management combined with stateless JWT handling. It includes token expiration, refresh mechanisms, single-session enforcement, an audit table to track client IP addresses, and a fallback mechanism to authenticate with LDAP or the database.

The steps involve:
	1.	JWT Generation and Validation: Tokens will be generated with expiration and role details but validated separately against the database for the user session and IP address.
	2.	Single Session Enforcement: Maintain a session store for active users to ensure only one active session per user.
	3.	LDAP and Database Authentication: Attempt LDAP authentication first, then fallback to database authentication.
	4.	Audit Table: Track client IP and store login attempts or token usage.

Project Setup

You’ll need the following dependencies in your pom.xml:

<dependencies>
    <!-- Spring Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>

    <!-- JWT -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt</artifactId>
        <version>0.9.1</version>
    </dependency>

    <!-- Spring Data JPA -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>

    <!-- LDAP -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-ldap</artifactId>
    </dependency>

    <!-- H2 Database (or use your choice of database) -->
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
</dependencies>

Configuration

Create the following components step-by-step:

1. JWT Utility

Utility class for token creation, validation, and parsing.

package com.example.security.jwt;

import io.jsonwebtoken.*;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {

    private final String secretKey = "your_secret_key"; // Replace with a strong key
    private final long jwtExpirationMs = 1000 * 60 * 60; // 1 hour
    private final long refreshExpirationMs = 1000 * 60 * 60 * 24; // 24 hours

    public String generateToken(String username, String roles) {
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }

    public String generateRefreshToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpirationMs))
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractRoles(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("roles", String.class);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }
}

2. Audit Table

Entity class to store user IP address and session details.

package com.example.security.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "audit_logs")
public class AuditLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String ipAddress;

    private String jwtToken;

    private LocalDateTime loginTime;

    private LocalDateTime logoutTime;

    private boolean isActive;
}

3. Audit Repository

Spring Data repository for audit table.

package com.example.security.repository;

import com.example.security.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    Optional<AuditLog> findByUsernameAndIpAddressAndIsActive(String username, String ipAddress, boolean isActive);
}

4. JWT Filter

A filter to handle JWT validation and ensure single-session enforcement.

package com.example.security.jwt;

import com.example.security.repository.AuditLogRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final AuditLogRepository auditLogRepository;

    public JwtTokenFilter(JwtUtil jwtUtil, AuditLogRepository auditLogRepository) {
        this.jwtUtil = jwtUtil;
        this.auditLogRepository = auditLogRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwtToken = authHeader.substring(7);
            String username = jwtUtil.extractUsername(jwtToken);

            if (jwtUtil.validateToken(jwtToken)) {
                String clientIp = request.getRemoteAddr();

                boolean isSessionActive = auditLogRepository.findByUsernameAndIpAddressAndIsActive(username, clientIp, true).isPresent();
                if (isSessionActive) {
                    // Add the authentication to the security context
                    JwtAuthenticationToken authentication = new JwtAuthenticationToken(username, jwtUtil.extractRoles(jwtToken));
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Session is not active or IP address mismatch");
                    return;
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}

5. Security Configuration

Set up security rules and attach the JWT filter.

package com.example.security.config;

import com.example.security.jwt.JwtTokenFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final JwtTokenFilter jwtTokenFilter;

    public SecurityConfig(JwtTokenFilter jwtTokenFilter) {
        this.jwtTokenFilter = jwtTokenFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests()
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated();

        http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}

This structure provides a robust, scalable implementation with JWT handling, token validation, single-session enforcement, and auditing. Let me know if you need further details or additional features!

Related queries:
a. Would you like to see a sample controller for user login and token issuance?
b. Should we integrate Redis for distributed session management?



/////////////////////////////


The choice between using a ConcurrentHashMap or Spring Security’s session management for storing session details like JWT tokens depends on your application’s requirements. Here’s a breakdown of each approach:

1. ConcurrentHashMap

When to Use:
	•	Short-term or custom in-memory storage:
If your use case involves temporarily storing tokens (e.g., for testing, proof of concept, or very lightweight applications).
	•	No framework dependency:
If you are not using Spring Security or want complete control over session handling.
	•	Token Revocation:
If you want to explicitly track and manage active tokens in-memory for purposes like token invalidation or blacklisting.
	•	High Concurrency Needs:
The ConcurrentHashMap provides thread-safe access to shared data, making it a reasonable choice for lightweight, in-memory session storage.

Why Use ConcurrentHashMap?
	•	Easy to implement and manage.
	•	Lightweight, with no external dependencies.
	•	Useful for simple applications with low traffic or no distributed architecture.

Drawbacks of ConcurrentHashMap:
	•	No built-in session expiration: You’ll need to manually handle token expiration or cleanup, which can lead to memory issues.
	•	Not suitable for distributed systems: Tokens stored in ConcurrentHashMap are only available in the instance of the application where they were added. For scalability, you’ll need additional infrastructure like Redis.
	•	No Spring Security integration: You lose out on Spring Security’s features like built-in authentication, authorization, and session handling.

2. Spring Security Session Management

When to Use:
	•	Secure and scalable applications: Use Spring Security if your application has user authentication/authorization or requires adherence to security best practices.
	•	Integration with Spring Security: Spring Security provides session management features like concurrency control, session invalidation, and automatic token expiration.
	•	Distributed Systems: If you need distributed session management, you can integrate Spring Security with external session stores like Redis, JDBC, or Hazelcast.
	•	Built-in JWT Support: Spring Security (with the help of libraries like Spring Security OAuth2 or custom filters) can handle JWT authentication, storing only user context (and not the token itself) in the SecurityContext.

Why Use Spring Security Session Management?
	•	Built-in features: Handles session expiration, invalidation, and concurrency control out of the box.
	•	Scalability: Supports integration with external session stores for distributed session management.
	•	Secure defaults: Adheres to secure practices for managing user sessions and authentication context.
	•	Framework alignment: If you’re already using Spring Boot/Spring Security, sticking to the framework’s tools avoids unnecessary duplication.

Drawbacks of Spring Security Session Management:
	•	Slightly more complex setup if you have custom requirements (e.g., custom JWT handling).
	•	Requires integration with external stores like Redis for scalability.

Recommendation:
	•	Use Spring Security session management if:
	•	You need a secure, scalable, and robust session management solution.
	•	You are building a production-grade application with user authentication and authorization.
	•	You require distributed session management in a microservices environment.
	•	Use ConcurrentHashMap if:
	•	The application is simple, lightweight, or for temporary use cases.
	•	There are no strict scalability requirements, and token management is handled entirely in-memory.
	•	You need full control over token storage and retrieval without depending on Spring Security.

Why Spring Security is Preferred for JWTs:
	•	Stateless Authentication: JWTs are typically used for stateless authentication, meaning you don’t need to store them server-side (not even in a ConcurrentHashMap). Instead, validate the JWT on every request (using public/private key pairs or shared secrets).
	•	Token Revocation: If revocation or blacklisting is needed, use a distributed cache like Redis rather than an in-memory map.

Conclusion:
For production use cases, especially in a Spring-based application, prefer Spring Security session management combined with stateless JWT handling for authentication. If tokens must be stored server-side (e.g., for blacklisting), use a distributed store like Redis rather than ConcurrentHashMap.

Related queries to consider:
a. Do you need a code example for Spring Security with JWT authentication?
b. Should we use Redis or a database for storing blacklisted JWTs?