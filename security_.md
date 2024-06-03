Step-by-Step Plan
Add Dependencies for Spring Security and JPA
Configure Spring Security for JWT-based Authentication and Role-based Authorization
Ensure JWT tokens do not work for other IPs or machines.
Create User Registration and Secure Password Storage
Implement hashing algorithms for password storage.
Create a user registration endpoint.
Implement temporary password generation and expiration.
Create a user login endpoint requiring a temporary password and prompting for a password reset on the first login.
Implement password reset functionality.
Implement Refresh JWT Token Generation and Validation for Session Management
Store User Details, Roles, User Session, and Client IP Addresses in the Database
Implement Response Encryption with Strong AES Algorithms
Ensure the client generates the same AES key as the backend.
Implement Hybrid Encryption for API Payload Encryption
Client generates a random AES key to encrypt the payload with AES.
AES key is encrypted with RSA public key and attached to the API payload.
Create Filters to Separate Security Tasks
Configure RequestDecryptionFilter and ResponseEncryptionFilter to apply to all requests and responses.
Enable CSRF protection.
1. Add Dependencies
Add the following dependencies to your pom.xml:

xml
Copy code
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-mail</artifactId>
</dependency>
<dependency>
    <groupId>com.google.crypto.tink</groupId>
    <artifactId>tink</artifactId>
    <version>1.5.0</version>
</dependency>
2. Configure Spring Security
Create a security configuration class:

java
Copy code
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            .antMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }
}
3. User Registration and Secure Password Storage
Create entities, services, and controllers for user registration and password management:

User Entity
java
Copy code
import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String password;
    private String email;
    private String role;
    private String temporaryPassword;
    private LocalDateTime tempPasswordExpiration;

    // getters and setters
}
User Repository
java
Copy code
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
}
User Service
java
Copy code
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public void registerUser(String username, String email) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setRole("ROLE_USER");
        String tempPassword = UUID.randomUUID().toString();
        user.setTemporaryPassword(passwordEncoder.encode(tempPassword));
        user.setTempPasswordExpiration(LocalDateTime.now().plusHours(24));
        userRepository.save(user);
        // Send tempPassword via email
    }

    public void resetPassword(String username, String newPassword) {
        User user = userRepository.findByUsername(username).orElseThrow();
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setTemporaryPassword(null);
        user.setTempPasswordExpiration(null);
        userRepository.save(user);
    }
}
Security Configuration for JWT
java
Copy code
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtTokenUtil {

    @Value("${jwt.secret}")
    private String secret;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails, String clientIp) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("ip", clientIp);
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.HS256, secret).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails, String clientIp) {
        final String username = extractUsername(token);
        final String tokenIp = extractAllClaims(token).get("ip", String.class);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token) && tokenIp.equals(clientIp));
    }
}
4. Refresh JWT Token Generation and Validation
Implement a service for refreshing JWT tokens:

java
Copy code
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtRefreshService {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    public String refreshToken(String oldToken, UserDetails userDetails, String clientIp) {
        if (jwtTokenUtil.isTokenExpired(oldToken)) {
            return jwtTokenUtil.generateToken(userDetails, clientIp);
        }
        return null;
    }
}
5. Storing User Details and Roles
Add additional fields to the User entity for roles and client IP addresses. Use JPA to store and retrieve these details.

6. Response Encryption with AES
Configure AES encryption for responses:

java
Copy code
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESEncryptionUtil {

    private static final String ALGORITHM = "AES";

    public static String generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static String encrypt(String data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(Base64.getDecoder().decode(key), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decrypt(String encryptedData, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(Base64.getDecoder().decode(key), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decodedData));
    }
}
7. Hybrid Encryption for API Payload
Implement hybrid encryption with RSA and AES:

java
Copy code
import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAEncryptionUtil {

    private static final String ALGORITHM = "RSA";

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static String encrypt(String data, String publicKeyStr) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStr)));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }
}
8. Filters for Security Tasks
Create and configure filters:

RequestDecryptionFilter
java
Copy code
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;

public class RequestDecryptionFilter implements javax.servlet.Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String encryptedPayload = httpServletRequest.getHeader("Encrypted-Payload");
        String aesKey = httpServletRequest.getHeader("AES-Key");

        // Decrypt payload and set it in request
        String decryptedPayload = AESEncryptionUtil.decrypt(encryptedPayload, aesKey);
        HttpServletRequestWrapper requestWrapper = new HttpServletRequestWrapper(httpServletRequest) {
            @Override
            public String getParameter(String name) {
                return decryptedPayload; // Modify as per your requirement
            }
        };

        chain.doFilter(requestWrapper, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void destroy() {}
}
ResponseEncryptionFilter
java
Copy code
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ResponseEncryptionFilter implements javax.servlet.Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        // Encrypt the response payload
        String payload = "Response Payload"; // Retrieve your actual payload
        String key = "AES Key"; // Retrieve your actual key

        String encryptedPayload = AESEncryptionUtil.encrypt(payload, key);
        httpServletResponse.setHeader("Encrypted-Payload", encryptedPayload);
        httpServletResponse.setHeader("AES-Key", key);

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void destroy() {}
}
Register Filters
java
Copy code
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            .antMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .addFilterBefore(new RequestDecryptionFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(new ResponseEncryptionFilter(), RequestDecryptionFilter.class)
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }
}


+++++++++++++++++++++++++

The provided RequestDecryptionFilter and ResponseEncryptionFilter need slight adjustments to ensure that all requests are decrypted and all responses are encrypted. Let's refine these filters to ensure they work correctly and are applied to all requests and responses.

Adjusting RequestDecryptionFilter and ResponseEncryptionFilter
Here are the refined versions of the filters:

RequestDecryptionFilter
This filter will decrypt the request body if the Encrypted-Payload and AES-Key headers are present.

java
Copy code
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class RequestDecryptionFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String encryptedPayload = httpRequest.getHeader("Encrypted-Payload");
        String aesKey = httpRequest.getHeader("AES-Key");

        if (encryptedPayload != null && aesKey != null) {
            try {
                String decryptedPayload = AESEncryptionUtil.decrypt(encryptedPayload, aesKey);
                HttpServletRequestWrapper requestWrapper = new HttpServletRequestWrapper(httpRequest) {
                    @Override
                    public ServletInputStream getInputStream() throws IOException {
                        final byte[] bytes = decryptedPayload.getBytes(StandardCharsets.UTF_8);
                        return new ServletInputStream() {
                            private int lastIndexRetrieved = -1;
                            private ReadListener readListener = null;

                            @Override
                            public boolean isFinished() {
                                return (lastIndexRetrieved == bytes.length - 1);
                            }

                            @Override
                            public boolean isReady() {
                                return isFinished();
                            }

                            @Override
                            public void setReadListener(ReadListener readListener) {
                                this.readListener = readListener;
                                if (!isFinished()) {
                                    try {
                                        readListener.onDataAvailable();
                                    } catch (IOException e) {
                                        readListener.onError(e);
                                    }
                                } else {
                                    try {
                                        readListener.onAllDataRead();
                                    } catch (IOException e) {
                                        readListener.onError(e);
                                    }
                                }
                            }

                            @Override
                            public int read() throws IOException {
                                int i;
                                if (!isFinished()) {
                                    i = bytes[lastIndexRetrieved + 1];
                                    lastIndexRetrieved++;
                                    if (isFinished() && (readListener != null)) {
                                        try {
                                            readListener.onAllDataRead();
                                        } catch (IOException ex) {
                                            readListener.onError(ex);
                                            throw ex;
                                        }
                                    }
                                    return i;
                                } else {
                                    return -1;
                                }
                            }
                        };
                    }

                    @Override
                    public BufferedReader getReader() throws IOException {
                        return new BufferedReader(new InputStreamReader(this.getInputStream()));
                    }
                };

                chain.doFilter(requestWrapper, response);
            } catch (Exception e) {
                throw new ServletException("Decryption failed", e);
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void destroy() {}
}
ResponseEncryptionFilter
This filter will encrypt the response body using the AES algorithm.

java
Copy code
import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.CharArrayWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class ResponseEncryptionFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        CharResponseWrapper responseWrapper = new CharResponseWrapper(httpServletResponse);

        chain.doFilter(request, responseWrapper);

        String key = "AES Key"; // Retrieve your actual key, e.g., from the request or a shared secret

        try {
            String encryptedPayload = AESEncryptionUtil.encrypt(responseWrapper.toString(), key);
            httpServletResponse.setHeader("Encrypted-Payload", encryptedPayload);
            httpServletResponse.setHeader("AES-Key", key);
            httpServletResponse.getOutputStream().write(encryptedPayload.getBytes());
        } catch (Exception e) {
            throw new ServletException("Encryption failed", e);
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void destroy() {}

    private static class CharResponseWrapper extends HttpServletResponseWrapper {
        private final CharArrayWriter charWriter = new CharArrayWriter();

        public CharResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        @Override
        public PrintWriter getWriter() {
            return new PrintWriter(charWriter);
        }

        @Override
        public String toString() {
            return charWriter.toString();
        }
    }
}
Registering the Filters
Ensure the filters are registered correctly in your security configuration:

java
Copy code
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            .antMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .addFilterBefore(new RequestDecryptionFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(new ResponseEncryptionFilter(), RequestDecryptionFilter.class)
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }
}
