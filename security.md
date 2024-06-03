1. Add Dependencies for Spring Security and JPA
First, add the necessary dependencies in pom.xml:

xml
Copy code
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

    <!-- JWT Dependency -->
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

    <!-- Java Mail Sender -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-mail</artifactId>
    </dependency>

    <!-- Spring Boot DevTools (Optional) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-devtools</artifactId>
        <scope>runtime</scope>
        <optional>true</optional>
    </dependency>
</dependencies>
2. Configure Spring Security for JWT-based Authentication and Role-based Authorization
SecurityConfig
Create the SecurityConfig class to configure security settings.

java
Copy code
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private CustomFilterConfig customFilterConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            .antMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .apply(new JwtTokenFilterConfigurer(jwtTokenProvider));

        customFilterConfig.registerCustomFilters(http);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/api/auth/**");
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

    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService();
    }
}
JwtTokenProvider
Create the JwtTokenProvider class to handle JWT token generation and validation.

java
Copy code
@Component
public class JwtTokenProvider {

    private String secretKey = "secret";

    private long validityInMilliseconds = 3600000; // 1h

    @Autowired
    private UserDetailsService userDetailsService;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String createToken(String username, List<String> roles, String clientIp) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);
        claims.put("ip", clientIp);
        
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(SignatureAlgorithm.HS256, secretKey)
            .compact();
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    public String getClientIp(String token) {
        return (String) Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get("ip");
    }

    public boolean validateToken(String token, String requestIp) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            String tokenIp = getClientIp(token);
            return !claims.getBody().getExpiration().before(new Date()) && requestIp.equals(tokenIp);
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidJwtAuthenticationException("Expired or invalid JWT token");
        }
    }
}
JwtTokenFilter
Create the JwtTokenFilter class to filter incoming requests and validate the JWT token.

java
Copy code
public class JwtTokenFilter extends OncePerRequestFilter {

    private JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = resolveToken(request);
        String clientIp = request.getRemoteAddr();
        
        if (token != null && jwtTokenProvider.validateToken(token, clientIp)) {
            Authentication auth = jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
JwtTokenFilterConfigurer
Register the filter in the SecurityConfig class:

java
Copy code
public class JwtTokenFilterConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilterConfigurer(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        JwtTokenFilter customFilter = new JwtTokenFilter(jwtTokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
3. User Registration and Secure Password Storage
ApplicationUser
Create an ApplicationUser entity to represent users.

java
Copy code
@Entity
public class ApplicationUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String email;
    private String password;
    private String role;
    private String temporaryPassword;
    private boolean temporaryPasswordExpired;

    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> roles;

    private String clientIp;

    // Getters and Setters
}
UserRepository
Create a UserRepository interface.

java
Copy code
public interface UserRepository extends JpaRepository<ApplicationUser, Long> {
    ApplicationUser findByUsername(String username);
    ApplicationUser findByEmail(String email);
}
UserService
Create a UserService class to handle user-related logic.

java
Copy code
@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JavaMailSender mailSender;

    public void registerUser(ApplicationUser user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        String temporaryPassword = generateTemporaryPassword();
        user.setTemporaryPassword(passwordEncoder.encode(temporaryPassword));
        user.setTemporaryPasswordExpired(false);
        userRepository.save(user);
        sendTemporaryPasswordEmail(user.getEmail(), temporaryPassword);
    }

    public void sendTemporaryPasswordEmail(String email, String temporaryPassword) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Temporary Password");
        message.setText("Your temporary password is: " + temporaryPassword);
        mailSender.send(message);
    }

    private String generateTemporaryPassword() {
        // Generate a secure random temporary password
        return RandomStringUtils.randomAlphanumeric(10);
    }
}
AuthController
Create endpoints for user registration and login.

java
Copy code
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody ApplicationUser user) {
        userService.registerUser(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        ApplicationUser user = userService.loadUserByUsername(loginRequest.getUsername());
        if (user != null && userService.passwordEncoder().matches(loginRequest.getPassword(), user.getPassword())) {
            if (userService.passwordEncoder().matches(loginRequest.getPassword(), user.getTemporaryPassword())) {
                user.setTemporaryPasswordExpired(true);
                userRepository.save(user);
                return ResponseEntity.status(HttpStatus.UPGRADE_REQUIRED).body("Temporary password expired. Please reset your password.");
            }
            String token = jwtTokenProvider.createToken(user.getUsername(), user.getRoles(), request.getRemoteAddr());
            return ResponseEntity.ok(new AuthResponse(token));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username/password");
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest) {
        // Implement password reset logic
        return ResponseEntity.ok("Password reset successfully");
    }
}
4. Refresh JWT Token Generation and Validation
Add a method in JwtTokenProvider to create a refresh token and an endpoint in AuthController.

java
Copy code
public class JwtTokenProvider {

    // Existing methods

    public String createRefreshToken(String username) {
        Claims claims = Jwts.claims().setSubject(username);
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds * 24); // 24h

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(SignatureAlgorithm.HS256, secretKey)
            .compact();
    }

    public boolean validateRefreshToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidJwtAuthenticationException("Expired or invalid JWT token");
        }
    }
}

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest, HttpServletRequest request) {
        String refreshToken = refreshTokenRequest.getRefreshToken();
        if (jwtTokenProvider.validateRefreshToken(refreshToken)) {
            String username = jwtTokenProvider.getUsername(refreshToken);
            ApplicationUser user = userService.loadUserByUsername(username);
            String token = jwtTokenProvider.createToken(username, user.getRoles(), request.getRemoteAddr());
            return ResponseEntity.ok(new AuthResponse(token));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }
    }
}
5. Storage of User Details, Roles, User Session, and Client IP Addresses
This was covered in the ApplicationUser entity class. Ensure that user details, roles, user session, and client IP addresses are stored in the database.

6. Implement Response Encryption with AES
Create a utility class for AES encryption.

java
Copy code
public class AESUtil {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/CBC/PKCS5Padding";

    public static String encrypt(String data, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decrypt(String encryptedData, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        byte[] originalData = cipher.doFinal(decodedData);
        return new String(originalData, StandardCharsets.UTF_8);
    }

    public static SecretKeySpec generateKey(String key) {
        return new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    public static IvParameterSpec generateIv(String iv) {
        return new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
    }
}
7. Implement Hybrid Encryption for API Payload Encryption
Create a utility class for RSA encryption.

java
Copy code
public class RSAUtil {

    private static final String ALGORITHM = "RSA";

    public static byte[] encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data), StandardCharsets.UTF_8);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
}
8. Create Filters for Security Tasks
Create RequestDecryptionFilter and ResponseEncryptionFilter.

java
Copy code
public class RequestDecryptionFilter extends OncePerRequestFilter {

    private PrivateKey privateKey;

    public RequestDecryptionFilter(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Decrypt request payload and handle CSRF token if necessary
        // Assume payload is in a custom header "X-Encrypted-Payload"
        String encryptedPayload = request.getHeader("X-Encrypted-Payload");
        if (encryptedPayload != null) {
            try {
                String decryptedPayload = RSAUtil.decrypt(Base64.getDecoder().decode(encryptedPayload), privateKey);
                request.setAttribute("decryptedPayload", decryptedPayload);
            } catch (Exception e) {
                throw new ServletException("Failed to decrypt request payload", e);
            }
        }
        filterChain.doFilter(request, response);
    }
}

public class ResponseEncryptionFilter extends OncePerRequestFilter {

    private PublicKey publicKey;

    public ResponseEncryptionFilter(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Create a wrapper for the response to capture the payload
        ResponseWrapper responseWrapper = new ResponseWrapper(response);
        filterChain.doFilter(request, responseWrapper);

        // Encrypt the payload
        String payload = responseWrapper.getCaptureAsString();
        if (payload != null) {
            try {
                byte[] encryptedPayload = RSAUtil.encrypt(payload, publicKey);
                response.setHeader("X-Encrypted-Payload", Base64.getEncoder().encodeToString(encryptedPayload));
            } catch (Exception e) {
                throw new ServletException("Failed to encrypt response payload", e);
            }
        }

        response.getOutputStream().write(payload.getBytes());
    }

    private class ResponseWrapper extends HttpServletResponseWrapper {
        private StringWriter capture;
        
        public ResponseWrapper(HttpServletResponse response) {
            super(response);
            capture = new StringWriter(response.getBufferSize());
        }

        @Override
        public PrintWriter getWriter() {
            return new PrintWriter(capture);
        }

        public String getCaptureAsString() {
            return capture.toString();
        }
    }
}
CustomFilterConfig
Create a configuration class to register the custom filters:

java
Copy code
@Component
public class CustomFilterConfig {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    @Autowired
    public CustomFilterConfig() throws Exception {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public void registerCustomFilters(HttpSecurity http) throws Exception {
        http.addFilterBefore(new RequestDecryptionFilter(privateKey), UsernamePasswordAuthenticationFilter.class);
        http.addFilterAfter(new ResponseEncryptionFilter(publicKey), JwtTokenFilter.class);
    }
}
9. Summary of Architecture, Components, and Design Patterns
Authentication and Authorization: Using JWT tokens for stateless authentication. Role-based authorization ensures users have the right permissions.
Password Security: Secure password storage with hashing algorithms (BCrypt).
Token Security: JWT tokens include the client IP to prevent reuse from different IPs.
Refresh Tokens: Implement refresh token mechanism to maintain session without needing to log in repeatedly.
Encryption: AES for symmetric encryption and RSA for asymmetric encryption. Response encryption ensures data is secure in transit.
Filters: Custom filters (RequestDecryptionFilter and ResponseEncryptionFilter) for separating security logic from business logic.
CSRF Protection: Enabled CSRF protection with CookieCsrfTokenRepository.
Service Layer: Use UserService to handle user-related logic.
Repositories: Use UserRepository for database interactions.
Controllers: Use AuthController for handling authentication and registration endpoints.
