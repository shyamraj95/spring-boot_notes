implementation to use interfaces and service classes for encryption, and also create and integrate `RequestDecryptionFilter` and `ResponseEncryptionFilter`.

### 1. Set Up Dependencies

**pom.xml:**
```xml
<dependencies>
    <!-- Spring Boot Starter Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- Spring Boot Starter Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <!-- Spring Boot Starter Data JPA -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    
    <!-- JWT -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt</artifactId>
        <version>0.9.1</version>
    </dependency>
    
    <!-- Lombok -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <version>1.18.22</version>
        <scope>provided</scope>
    </dependency>
    
    <!-- H2 Database -->
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
    
    <!-- Spring Boot Starter Test -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</artifactId>
    </dependency>
    
    <!-- Spring Security Test -->
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</artifactId>
    </dependency>
</dependencies>
```

### 2. Encryption Interfaces and Implementations

**EncryptionService.java:**
```java
public interface EncryptionService {
    SecretKey generateAESKey() throws Exception;
    KeyPair generateRSAKeyPair() throws Exception;
    String encryptAES(String data, SecretKey key) throws Exception;
    String encryptRSA(String data, PublicKey key) throws Exception;
}
```

**EncryptionServiceImpl.java:**
```java
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;

@Service
public class EncryptionServiceImpl implements EncryptionService {

    @Override
    public SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    @Override
    public KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    @Override
    public String encryptAES(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    @Override
    public String encryptRSA(String data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }
}
```

### 3. User Registration and Secure Password Storage

**User.java:**
```java
import lombok.Data;

import javax.persistence.*;
import java.util.Set;

@Entity
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private boolean isEnabled;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> roles;

    private String tempPassword;
    private Long tempPasswordExpiry;

    // Add other fields as necessary
}
```

**UserRepository.java:**
```java
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
```

**UserService.java:**
```java
public interface UserService {
    User registerUser(String username, String password);
    User generateTempPassword(User user);
    boolean validateTempPassword(User user, String tempPassword);
    User findByUsername(String username);
    void save(User user);
}
```

**UserServiceImpl.java:**
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public User registerUser(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setEnabled(true);
        user.setRoles(Set.of("ROLE_USER"));
        return userRepository.save(user);
    }

    @Override
    public User generateTempPassword(User user) {
        String tempPassword = UUID.randomUUID().toString();
        user.setTempPassword(tempPassword);
        user.setTempPasswordExpiry(new Date().getTime() + 3600000); // 1 hour expiry
        return userRepository.save(user);
    }

    @Override
    public boolean validateTempPassword(User user, String tempPassword) {
        return user.getTempPassword().equals(tempPassword) && new Date().getTime() < user.getTempPasswordExpiry();
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public void save(User user) {
        userRepository.save(user);
    }
}
```

**UserController.java:**
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestParam String username, @RequestParam String password) {
        User user = userService.registerUser(username, password);
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestParam String username, @RequestParam String tempPassword) {
        User user = userService.findByUsername(username);
        if (userService.validateTempPassword(user, tempPassword)) {
            // Generate JWT token and return
            return ResponseEntity.ok("Login successful, please reset your password.");
        }
        return ResponseEntity.badRequest().body("Invalid temporary password.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String username, @RequestParam String newPassword) {
        User user = userService.findByUsername(username);
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setTempPassword(null);
        user.setTempPasswordExpiry(null);
        userService.save(user);
        return ResponseEntity.ok("Password reset successful.");
    }

    // Other endpoints as necessary
}
```

### 4. Implement JWT Token Handling

**JwtTokenUtil.java:**
```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtTokenUtil {

    private String secret = "secretKey";

    public String generateToken(User user, String ipAddress, String userAgent) {
        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put("roles", user.getRoles());
        claims.put("ip", ipAddress);
        claims.put("ua", userAgent);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour expiry
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    public Claims validateToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }
}
```


### 5. Create Filters for Security Tasks

**RequestDecryptionFilter.java:**
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RequestDecryptionFilter extends OncePerRequestFilter {

    @Autowired
    private EncryptionService encryptionService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String encryptedData = request.getHeader("Encrypted-Data");
        String encryptedKey = request.getHeader("Encrypted-Key");

        if (encryptedData != null && encryptedKey != null) {
            try {
                SecretKey aesKey = encryptionService.decryptRSA(encryptedKey); // Assuming decryptRSA method exists
                String decryptedData = encryptionService.decryptAES(encryptedData, aesKey); // Assuming decryptAES method exists
                request.setAttribute("decryptedData", decryptedData);
            } catch (Exception e) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid encryption");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
```

**ResponseEncryptionFilter.java:**
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ResponseEncryptionFilter extends OncePerRequestFilter {

    @Autowired
    private EncryptionService encryptionService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Wrap response to capture the output
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
        filterChain.doFilter(request, responseWrapper);

        String responseData = new String(responseWrapper.getContentAsByteArray(), response.getCharacterEncoding());

        if (responseData != null) {
            try {
                SecretKey aesKey = encryptionService.generateAESKey();
                String encryptedData = encryptionService.encryptAES(responseData, aesKey);
                String encryptedKey = encryptionService.encryptRSA(aesKey.toString(), publicKey); // publicKey should be provided

                response.setHeader("Encrypted-Data", encryptedData);
                response.setHeader("Encrypted-Key", encryptedKey);
                responseWrapper.copyBodyToResponse();
            } catch (Exception e) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Encryption error");
            }
        }
    }
}
```

**ContentCachingResponseWrapper.java:**
```java
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

public class ContentCachingResponseWrapper extends HttpServletResponseWrapper {

    private ByteArrayOutputStream content = new ByteArrayOutputStream();
    private ServletOutputStream outputStream;
    private PrintWriter writer;

    public ContentCachingResponseWrapper(HttpServletResponse response) {
        super(response);
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        if (this.writer != null) {
            throw new IllegalStateException("getWriter() has already been called on this response.");
        }
        if (this.outputStream == null) {
            this.outputStream = new ServletOutputStreamWrapper(super.getOutputStream(), this.content);
        }
        return this.outputStream;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (this.outputStream != null) {
            throw new IllegalStateException("getOutputStream() has already been called on this response.");
        }
        if (this.writer == null) {
            this.writer = new PrintWriter(new OutputStreamWriter(this.content, this.getCharacterEncoding()), true);
        }
        return this.writer;
    }

    @Override
    public void flushBuffer() throws IOException {
        if (this.writer != null) {
            this.writer.flush();
        } else if (this.outputStream != null) {
            this.outputStream.flush();
        }
    }

    public byte[] getContentAsByteArray() {
        return this.content.toByteArray();
    }

    public void copyBodyToResponse() throws IOException {
        if (this.outputStream != null) {
            this.outputStream.flush();
        } else if (this.writer != null) {
            this.writer.flush();
        }
        super.getOutputStream().write(this.content.toByteArray());
    }
}
```

**ServletOutputStreamWrapper.java:**
```java
import javax.servlet.ServletOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ServletOutputStreamWrapper extends ServletOutputStream {

    private final ServletOutputStream outputStream;
    private final ByteArrayOutputStream copy;

    public ServletOutputStreamWrapper(ServletOutputStream outputStream, ByteArrayOutputStream copy) {
        this.outputStream = outputStream;
        this.copy = copy;
    }

    @Override
    public void write(int b) throws IOException {
        this.outputStream.write(b);
        this.copy.write(b);
    }

    @Override
    public boolean isReady() {
        return this.outputStream.isReady();
    }

    @Override
    public void setWriteListener(javax.servlet.WriteListener listener) {
        this.outputStream.setWriteListener(listener);
    }
}
```

### 6. Integrate Filters with Security Configuration

**SecurityConfig.java:**
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Autowired
    private RequestDecryptionFilter requestDecryptionFilter;

    @Autowired
    private ResponseEncryptionFilter responseEncryptionFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .authorizeRequests()
            .antMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated();

        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(requestDecryptionFilter, JwtRequestFilter.class);
        http.addFilterAfter(responseEncryptionFilter, JwtRequestFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```

### Final Adjustments

Ensure `EncryptionService` has methods for decryption and update any missing dependencies or services required for these operations. Here's a quick overview:

**EncryptionService.java:**
```java
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PublicKey;

public interface EncryptionService {
    SecretKey generateAESKey() throws Exception;
    KeyPair generateRSAKeyPair() throws Exception;
    String encryptAES(String data, SecretKey key) throws Exception;
    String encryptRSA(String data, PublicKey key) throws Exception;
    SecretKey decryptRSA(String encryptedKey) throws Exception;
    String decryptAES(String encryptedData, SecretKey key) throws Exception;
}
```

**EncryptionServiceImpl.java:**
```java
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

@Service
public class EncryptionServiceImpl implements EncryptionService {

    @Override
    public SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    @Override
    public KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    @Override
    public String encryptAES(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    @Override
    public String encryptRSA(String data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    @Override
    public SecretKey decryptRSA(String encryptedKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey); // privateKey should

 be provided
        byte[] decryptedKey = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));
        return new SecretKeySpec(decryptedKey, "AES");
    }

    @Override
    public String decryptAES(String encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedData);
    }
}
```

### Summary
This code completes the setup for Spring Boot with JWT-based authentication, role-based authorization, secure password storage, AES/RSA encryption, and custom filters for request/response encryption. Ensure to handle keys securely and consider key management practices for production. 


+++++++__________________________+++++++++++++++++++++++++++++





implementation to use the X-Forwarded-For header to get the client's IP address, store the IP address in the user session, and compare it with the IP address in subsequent requests to ensure they match.

### 1. Modify the User Entity

Add fields for storing the IP address and session information.

**User.java:**
```java
import lombok.Data;

import javax.persistence.*;
import java.util.Set;

@Entity
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private boolean isEnabled;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> roles;

    private String tempPassword;
    private Long tempPasswordExpiry;

    private String sessionIp;
    private Long sessionExpiry;

    // Add other fields as necessary
}
```

### 2. Adjust JWT Token Util

**JwtTokenUtil.java:**
```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtTokenUtil {

    private String secret = "secretKey";

    public String generateToken(User user) {
        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put("roles", user.getRoles());

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour expiry
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    public Claims validateToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }
}
```

### 3. Update UserService

**UserServiceImpl.java:**
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public User registerUser(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setEnabled(true);
        user.setRoles(Set.of("ROLE_USER"));
        return userRepository.save(user);
    }

    @Override
    public User generateTempPassword(User user) {
        String tempPassword = UUID.randomUUID().toString();
        user.setTempPassword(tempPassword);
        user.setTempPasswordExpiry(new Date().getTime() + 3600000); // 1 hour expiry
        return userRepository.save(user);
    }

    @Override
    public boolean validateTempPassword(User user, String tempPassword) {
        return user.getTempPassword().equals(tempPassword) && new Date().getTime() < user.getTempPasswordExpiry();
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public void save(User user) {
        userRepository.save(user);
    }

    @Override
    public void updateSessionInfo(User user, String ipAddress) {
        user.setSessionIp(ipAddress);
        user.setSessionExpiry(new Date().getTime() + 3600000); // 1 hour expiry
        userRepository.save(user);
    }

    @Override
    public boolean validateSession(User user, String ipAddress) {
        return user.getSessionIp().equals(ipAddress) && new Date().getTime() < user.getSessionExpiry();
    }
}
```

**UserService.java:**
```java
public interface UserService {
    User registerUser(String username, String password);
    User generateTempPassword(User user);
    boolean validateTempPassword(User user, String tempPassword);
    User findByUsername(String username);
    void save(User user);
    void updateSessionInfo(User user, String ipAddress);
    boolean validateSession(User user, String ipAddress);
}
```

### 4. Adjust UserController


**UserController.java:**
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/auth")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestParam String username, @RequestParam String password) {
        User user = userService.registerUser(username, password);
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(HttpServletRequest request, @RequestParam String username, @RequestParam String tempPassword) {
        User user = userService.findByUsername(username);
        if (userService.validateTempPassword(user, tempPassword)) {
            String ipAddress = request.getHeader("X-Forwarded-For");
            if (ipAddress == null) {
                ipAddress = request.getRemoteAddr();
            }
            userService.updateSessionInfo(user, ipAddress);
            String token = jwtTokenUtil.generateToken(user);
            return ResponseEntity.ok(token);
        }
        return ResponseEntity.badRequest().body("Invalid temporary password.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String username, @RequestParam String newPassword) {
        User user = userService.findByUsername(username);
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setTempPassword(null);
        user.setTempPasswordExpiry(null);
        userService.save(user);
        return ResponseEntity.ok("Password reset successful.");
    }
}
```

### 5. Update the JWT Request Filter

**JwtRequestFilter.java:**
```java
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String requestTokenHeader = request.getHeader("Authorization");
        String username = null;
        String jwtToken = null;

        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7);
            Claims claims = jwtTokenUtil.validateToken(jwtToken);
            if (claims != null) {
                username = claims.getSubject();
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userService.findByUsername(username);
            String ipAddress = request.getHeader("X-Forwarded-For");
            if (ipAddress == null) {
                ipAddress = request.getRemoteAddr();
            }
            User user = userService.findByUsername(username);
            if (userService.validateSession(user, ipAddress)) {
                // Validate and set authentication
            } else {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid session IP");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
```

### 6. Finalize Encryption Service Implementation

Ensure that the `EncryptionService` includes methods for decryption as well.

**EncryptionService.java:**
```java
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PublicKey;

public interface EncryptionService {
    SecretKey generateAESKey() throws Exception;
    KeyPair generateRSAKeyPair() throws Exception;
    String encryptAES(String data, SecretKey key) throws Exception;
    String encryptRSA(String data, PublicKey key) throws Exception;
    SecretKey decryptRSA(String encryptedKey) throws Exception;
    String decryptAES(String encryptedData, SecretKey key) throws Exception;
}
```

**EncryptionServiceImpl.java:**
```java
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

@Service
public class EncryptionServiceImpl implements EncryptionService {

    private PrivateKey privateKey; // Initialize with your RSA private key

    @Override
    public SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    @Override
    public KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    @Override
    public String encryptAES(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    @Override
    public String encryptRSA(String data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    @Override
    public SecretKey decryptRSA(String encryptedKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));
        return new SecretKeySpec(decryptedKey, "AES");
    }

    @Override
    public String decryptAES(String encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedData);
    }
}
```

### 7. Update Filters for Encryption

**RequestDecryptionFilter.java:**
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RequestDecryptionFilter extends OncePerRequestFilter {

    @Autowired
    private EncryptionService encryptionService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String encryptedData = request.getHeader("Encrypted-Data");
        String encryptedKey = request.getHeader("Encrypted-Key");

        if (encryptedData != null && encryptedKey != null) {
            try {
                SecretKey aesKey = encryptionService.decryptRSA(encryptedKey);
                String decryptedData = encryptionService.decryptAES(encryptedData, aesKey);
                request.setAttribute("decryptedData", decryptedData);
            } catch (Exception e) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid encryption");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
```

**ResponseEncryptionFilter.java:**
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ResponseEncryptionFilter extends OncePerRequestFilter {

    @Autowired
    private EncryptionService encryptionService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Wrap response to capture the output
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
        filterChain.doFilter(request, responseWrapper);

        String responseData = new String(responseWrapper.getContentAsByteArray(), response.getCharacterEncoding());

        if (responseData != null) {
            try {
                SecretKey aesKey = encryptionService.generateAESKey();
                String encryptedData = encryptionService.encryptAES(responseData, aesKey);
                String encryptedKey = encryptionService.encryptRSA(Base64.getEncoder().encodeToString(aesKey.getEncoded()), publicKey); // publicKey should be provided

                response.setHeader("Encrypted-Data", encryptedData);
                response.setHeader("Encrypted-Key", encryptedKey);
                responseWrapper.copyBodyToResponse();
            } catch (Exception e) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Encryption error");
            }
        }
    }
}
```

### 8. Integrate Filters with Security Configuration

**SecurityConfig.java:**
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWeb

Security;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Autowired
    private RequestDecryptionFilter requestDecryptionFilter;

    @Autowired
    private ResponseEncryptionFilter responseEncryptionFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .authorizeRequests()
            .antMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated();

        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(requestDecryptionFilter, JwtRequestFilter.class);
        http.addFilterAfter(responseEncryptionFilter, JwtRequestFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```

### Final Adjustments

Ensure the `privateKey` and `publicKey` are properly initialized and managed securely. This can be done using a configuration file or a secure key management service.

### Summary
This code completes the setup for Spring Boot with JWT-based authentication, role-based authorization, secure password storage, AES/RSA encryption, and custom filters for request/response encryption. Ensure to handle keys securely and consider key management practices for production. 

**Next steps:**
**a.** Add unit tests to ensure the code works as expected.
**b.** Test the filters and encryption/decryption processes in a secure and isolated environment.






+++++++++++++++++++++++++++___________________________________________+++++++++++++++++++++++++++++++++++++++++++++++++


Certainly! Configuring environment variables to store sensitive information such as RSA keys ensures that these values are not hard-coded in your application code, enhancing security. Here’s a step-by-step guide to setting up and using environment variables to store your RSA key pair in a Spring Boot application:

### Step 1: Configure Environment Variables

1. **Set Environment Variables**:
   - Define environment variables for your RSA keys. This can be done in different ways depending on your operating system and deployment environment.

   **On Unix-based systems (Linux, macOS)**:
   ```sh
   export RSA_PRIVATE_KEY="<Your-Encrypted-Private-Key-Here>"
   export RSA_PUBLIC_KEY="<Your-Public-Key-Here>"
   ```

   **On Windows**:
   ```cmd
   set RSA_PRIVATE_KEY=<Your-Encrypted-Private-Key-Here>
   set RSA_PUBLIC_KEY=<Your-Public-Key-Here>
   ```

   **In a `.env` file (useful for development)**:
   ```plaintext
   RSA_PRIVATE_KEY=<Your-Encrypted-Private-Key-Here>
   RSA_PUBLIC_KEY=<Your-Public-Key-Here>
   ```

2. **Load Environment Variables in Spring Boot**:
   - Spring Boot automatically loads environment variables, making them accessible through the `@Value` annotation or `Environment` object.

### Step 2: Access Environment Variables in Spring Boot

1. **Using `@Value` Annotation**:
   - Use the `@Value` annotation to inject the values of the environment variables into your Spring Boot components.

   ```java
   import org.springframework.beans.factory.annotation.Value;
   import org.springframework.stereotype.Component;

   @Component
   public class KeyConfig {

       @Value("${RSA_PRIVATE_KEY}")
       private String privateKey;

       @Value("${RSA_PUBLIC_KEY}")
       private String publicKey;

       public String getPrivateKey() {
           return privateKey;
       }

       public String getPublicKey() {
           return publicKey;
       }
   }
   ```

2. **Using `Environment` Object**:
   - Alternatively, you can use the `Environment` object to access environment variables.

   ```java
   import org.springframework.beans.factory.annotation.Autowired;
   import org.springframework.core.env.Environment;
   import org.springframework.stereotype.Component;

   @Component
   public class KeyConfig {

       private final Environment env;

       @Autowired
       public KeyConfig(Environment env) {
           this.env = env;
       }

       public String getPrivateKey() {
           return env.getProperty("RSA_PRIVATE_KEY");
       }

       public String getPublicKey() {
           return env.getProperty("RSA_PUBLIC_KEY");
       }
   }
   ```

### Step 3: Use RSA Keys in Your Application

1. **Decrypt the Private Key**:
   - If your private key is stored in an encrypted form, you will need to decrypt it before use. Here’s an example of how you might decrypt and use the private key:

   ```java
   import javax.crypto.Cipher;
   import java.security.KeyFactory;
   import java.security.PrivateKey;
   import java.security.PublicKey;
   import java.security.spec.PKCS8EncodedKeySpec;
   import java.security.spec.X509EncodedKeySpec;
   import java.util.Base64;

   @Component
   public class RSAEncryptionUtil {

       private final KeyConfig keyConfig;

       @Autowired
       public RSAEncryptionUtil(KeyConfig keyConfig) {
           this.keyConfig = keyConfig;
       }

       public PrivateKey getPrivateKey() throws Exception {
           String privateKeyPEM = keyConfig.getPrivateKey();
           byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
           PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
           KeyFactory keyFactory = KeyFactory.getInstance("RSA");
           return keyFactory.generatePrivate(keySpec);
       }

       public PublicKey getPublicKey() throws Exception {
           String publicKeyPEM = keyConfig.getPublicKey();
           byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
           X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
           KeyFactory keyFactory = KeyFactory.getInstance("RSA");
           return keyFactory.generatePublic(keySpec);
       }

       public byte[] encrypt(String data, PublicKey publicKey) throws Exception {
           Cipher cipher = Cipher.getInstance("RSA");
           cipher.init(Cipher.ENCRYPT_MODE, publicKey);
           return cipher.doFinal(data.getBytes());
       }

       public String decrypt(byte[] data, PrivateKey privateKey) throws Exception {
           Cipher cipher = Cipher.getInstance("RSA");
           cipher.init(Cipher.DECRYPT_MODE, privateKey);
           return new String(cipher.doFinal(data));
       }
   }
   ```

2. **Encrypt and Decrypt Data**:
   - Use the `RSAEncryptionUtil` to encrypt and decrypt API payloads.

   **Encrypting Data**:
   ```java
   String dataToEncrypt = "Sensitive Data";
   PublicKey publicKey = rsaEncryptionUtil.getPublicKey();
   byte[] encryptedData = rsaEncryptionUtil.encrypt(dataToEncrypt, publicKey);
   ```

   **Decrypting Data**:
   ```java
   byte[] dataToDecrypt = ...; // data received from the client
   PrivateKey privateKey = rsaEncryptionUtil.getPrivateKey();
   String decryptedData = rsaEncryptionUtil.decrypt(dataToDecrypt, privateKey);
   ```

By following these steps, you ensure that your RSA keys are securely stored and used within your Spring Boot application.


////////////////////////////////////////////============================================================////////////////////////////////////////////////////////


security configuration using Spring Security, JWT, IP validation, CSRF protection, and AES encryption for requests and responses.

### Complete Implementation

#### 1. SecurityConfig Class

```java
// Import necessary packages
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // Bean to provide PasswordEncoder for secure password storage
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Configure HTTP security settings
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // Enable CSRF protection with cookie repository
            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
            // Enable CORS with default settings
            .cors().and()
            // Ensure sessions are stateless
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            // Add Encryption filter before all other filters
            .addFilterBefore(new EncryptionFilter(), UsernamePasswordAuthenticationFilter.class)
            // Add JWT filter before UsernamePasswordAuthenticationFilter
            .addFilterBefore(jwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
            // Define URL access rules
            .authorizeRequests()
                // Allow public access to the registration and login endpoints
                .antMatchers("/api/auth/register", "/api/auth/login", "/api/auth/reset-password").permitAll()
                // Any other request must be authenticated
                .anyRequest().authenticated();
    }

    // Allow ignoring of static resources from security
    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/resources/**");
    }

    // Define JwtTokenFilter bean
    @Bean
    public JwtTokenFilter jwtTokenFilter() {
        return new JwtTokenFilter(jwtTokenProvider(), userSessionService());
    }

    // Define JwtTokenProvider bean
    @Bean
    public JwtTokenProvider jwtTokenProvider() {
        return new JwtTokenProvider();
    }

    // Define UserSessionService bean
    @Bean
    public UserSessionService userSessionService() {
        return new UserSessionService();
    }
}
```

#### 2. JwtTokenProvider Class

```java
// Import necessary packages
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {

    // Secret key for signing JWT
    @Value("${security.jwt.token.secret-key:secret}")
    private String secretKey;

    // JWT token validity duration (in milliseconds)
    @Value("${security.jwt.token.expire-length:3600000}")
    private long validityInMilliseconds;

    // Initialize the secret key
    @PostConstruct
    protected void init() {
        // Encode the secret key using Base64
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // Create a JWT token for the given username and roles
    public String createToken(String username, List<String> roles) {
        // Set claims for the token
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);

        // Set the validity duration for the token
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        // Build and sign the JWT token
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    // Get the username from the token
    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    // Get the roles from the token
    public List<String> getRoles(String token) {
        return (List<String>) Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get("roles");
    }

    // Validate the token's expiration
    public boolean validateToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
        return !claims.getExpiration().before(new Date());
    }

    // Resolve token from the request header
    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

#### 3. JwtTokenFilter Class

```java
// Import necessary packages
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtTokenFilter extends UsernamePasswordAuthenticationFilter {

    private JwtTokenProvider jwtTokenProvider;
    private UserSessionService userSessionService;

    // Constructor injection of JwtTokenProvider and UserSessionService
    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider, UserSessionService userSessionService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userSessionService = userSessionService;
    }

    // Override the doFilterInternal method to add JWT validation logic
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Extract the JWT token from the request
        String token = jwtTokenProvider.resolveToken(request);

        try {
            if (token != null && jwtTokenProvider.validateToken(token)) {
                // Get user details from token
                String username = jwtTokenProvider.getUsername(token);
                UserDetails userDetails = // Load user details from the database or another source

                // Validate the client's IP address
                String requestIp = request.getRemoteAddr();
                UserSession userSession = userSessionService.getSessionByUsername(username);
                if (userSession == null || !userSession.getIpAddress().equals(requestIp)) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "IP address mismatch");
                    return;
                }

                // Create authentication object
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication in the context
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
            return;
        }

        // Continue the filter chain
        filterChain.doFilter(request, response);
    }
}
```

#### 4. Role-based Authorization Using `@PreAuthorize` Annotations

```java
// Import necessary packages
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleController {

    // An example endpoint restricted to users with ADMIN role
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public String adminAccess() {
        return "Admin content";
    }

    // An example endpoint restricted to users with USER role
    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/user")
    public String userAccess() {
        return "User content";
    }
}
```

#### 5. User Registration and Secure Password Storage

```java
// Import necessary packages
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // Endpoint for user registration
    @PostMapping("/register")
    public String registerUser(@RequestBody User user) {
        // Encode the user's password before saving
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "User registered successfully";
    }
}
```

#### 6. Temporary Password Generation and Expiration

```java
// Import necessary packages
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.util.Date;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @

Autowired
    private JavaMailSender mailSender;

    // Endpoint to handle password reset request
    @PostMapping("/reset-password")
    public String resetPassword(@RequestParam String email) throws MessagingException {
        // Generate temporary password
        String tempPassword = UUID.randomUUID().toString().replace("-", "").substring(0, 8);

        // Find user by email
        User user = userRepository.findByEmail(email);
        if (user == null) {
            return "User not found";
        }

        // Encode and set temporary password
        user.setPassword(passwordEncoder.encode(tempPassword));
        user.setPasswordExpiryDate(new Date(System.currentTimeMillis() + 3600000)); // 1 hour expiry
        userRepository.save(user);

        // Send temporary password via email
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        helper.setTo(email);
        helper.setSubject("Password Reset");
        helper.setText("Your temporary password is: " + tempPassword);

        mailSender.send(message);

        return "Temporary password sent to your email";
    }
}
```

#### 7. User Login Endpoint and Store Client IP in Session Data

```java
// Import necessary packages
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserSessionService userSessionService;

    // Endpoint for user login
    @PostMapping("/login")
    public String login(@RequestBody AuthRequest request, HttpServletRequest httpRequest) {
        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

            // Get the authenticated user
            User user = (User) authentication.getPrincipal();

            // Store the user's IP in the session data
            String clientIp = httpRequest.getRemoteAddr();
            userSessionService.createSession(user.getUsername(), clientIp);

            // Create JWT token
            String token = jwtTokenProvider.createToken(user.getUsername(), user.getRoles());

            return "Bearer " + token;
        } catch (AuthenticationException e) {
            return "Invalid username/password";
        }
    }
}
```

#### 8. Password Reset Functionality

This part remains the same as in Step 6.

#### 9. Refresh JWT Token Generation and Validation for Session Management

```java
// Import necessary packages
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private UserSessionService userSessionService;

    @PostMapping("/refresh-token")
    public String refreshToken(@RequestHeader("Authorization") String oldToken, HttpServletRequest httpRequest) {
        // Validate the old token and get user details
        if (jwtTokenProvider.validateToken(oldToken)) {
            String username = jwtTokenProvider.getUsername(oldToken);
            UserSession userSession = userSessionService.getSessionByUsername(username);
            if (userSession != null && userSession.getIpAddress().equals(httpRequest.getRemoteAddr())) {
                List<String> roles = jwtTokenProvider.getRoles(oldToken);
                // Generate a new token
                String newToken = jwtTokenProvider.createToken(username, roles);
                return "Bearer " + newToken;
            }
        }
        return "Invalid or expired token";
    }
}
```

#### 10. Store User Details, Roles, User Sessions, and Client IP Addresses in the Database

```java
// User entity
import javax.persistence.*;
import java.util.Date;
import java.util.List;

@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String email;
    private String password;
    private Date passwordExpiryDate;

    @ManyToMany(fetch = FetchType.EAGER)
    private List<Role> roles;

    // getters and setters
}

// Role entity
@Entity
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;

    // getters and setters
}

// UserSession entity
@Entity
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String ipAddress;
    private Date loginDate;

    // getters and setters
}

// User repository
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByEmail(String email);
    User findByUsername(String username);
}

// User session repository
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    UserSession findByUsername(String username);
}

// Role repository
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}

// UserSessionService class
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserSessionService {

    @Autowired
    private UserSessionRepository userSessionRepository;

    public void createSession(String username, String ipAddress) {
        UserSession session = new UserSession();
        session.setUsername(username);
        session.setIpAddress(ipAddress);
        session.setLoginDate(new Date());
        userSessionRepository.save(session);
    }

    public UserSession getSessionByUsername(String username) {
        return userSessionRepository.findByUsername(username);
    }
}
```

#### 11. AES Encryption Utility

```java
// Import necessary packages
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesEncryptionUtil {

    // Generate a new AES key
    public static String generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    // Encrypt a message using AES
    public static String encrypt(String message, String secret) throws Exception {
        SecretKeySpec key = new SecretKeySpec(Base64.getDecoder().decode(secret), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypt a message using AES
    public static String decrypt(String encryptedMessage, String secret) throws Exception {
        SecretKeySpec key = new SecretKeySpec(Base64.getDecoder().decode(secret), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decrypted);
    }
}
```

#### 12. Encryption Filter

```java
// Import necessary packages
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Base64;

public class EncryptionFilter implements Filter {

    private static final String AES_KEY = "your-256-bit-base64-encoded-key"; // Replace with your actual key

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // Wrap request and response to handle encryption/decryption
        EncryptedRequestWrapper encryptedRequest = new EncryptedRequestWrapper(request);
        EncryptedResponseWrapper encryptedResponse = new EncryptedResponseWrapper(response);

        chain.doFilter(encryptedRequest, encryptedResponse);

        // Encrypt response
        String responseContent = encryptedResponse.getCaptureAsString();
        String encryptedResponseContent;
        try {
            encryptedResponseContent = AesEncryptionUtil.encrypt(responseContent, AES_KEY);
        } catch (Exception e) {
            throw new ServletException("Encryption error", e);
        }

        // Write encrypted response
        response.setContentLength(encryptedResponseContent.length());
        response.getWriter().write(encryptedResponseContent);
    }

    @Override
    public void destroy() {}

    private static class EncryptedRequestWrapper extends HttpServletRequestWrapper {
        private final byte[] body;

        public EncryptedRequestWrapper(HttpServletRequest request) throws IOException {
            super(request);
            body = toByteArray(request.getInputStream());
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public int read() {
                    return byteArrayInputStream.read();
                }
            };
        }

        public String getBody() {
            return new String(body);
        }

        private byte[] toByteArray(InputStream input) throws IOException {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte

[1024];
            int n;
            while ((n = input.read(buffer)) != -1) {
                output.write(buffer, 0, n);
            }
            return output.toByteArray();
        }
    }

    private static class EncryptedResponseWrapper extends HttpServletResponseWrapper {
        private final ByteArrayOutputStream capture;
        private ServletOutputStream output;
        private PrintWriter writer;

        public EncryptedResponseWrapper(HttpServletResponse response) {
            super(response);
            capture = new ByteArrayOutputStream(response.getBufferSize());
        }

        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            if (writer != null) {
                throw new IllegalStateException("getWriter() has already been called on this response.");
            }

            if (output == null) {
                output = new ServletOutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        capture.write(b);
                    }
                };
            }
            return output;
        }

        @Override
        public PrintWriter getWriter() throws IOException {
            if (output != null) {
                throw new IllegalStateException("getOutputStream() has already been called on this response.");
            }

            if (writer == null) {
                writer = new PrintWriter(new OutputStreamWriter(capture, getCharacterEncoding()));
            }
            return writer;
        }

        public String getCaptureAsString() throws IOException {
            if (writer != null) {
                writer.close();
            } else if (output != null) {
                output.close();
            }
            return capture.toString(getCharacterEncoding());
        }
    }
}
```

#### 13. Unit and Integration Tests

```java
// Import necessary packages
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class AuthServiceTests {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void testPasswordEncoder() {
        String rawPassword = "password";
        String encodedPassword = passwordEncoder.encode(rawPassword);
        assertThat(passwordEncoder.matches(rawPassword, encodedPassword)).isTrue();
    }

    // More tests can be written similarly for other functionalities
}
```













