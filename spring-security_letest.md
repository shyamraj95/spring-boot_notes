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
