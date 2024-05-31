https://github.com/migo-amao/authorization-service/tree/master

To design and implement a user registration, login with JWT authentication and authorization, and logout using Spring Security with proper design patterns, we will separate the logic into different layers and components. Here's a detailed plan:

1. **Background**: Provide context and explain the goal of the implementation.
2. **Requirements**: List functional and non-functional requirements using the MoSCoW prioritization method.
3. **Method**: Explain the architecture, components, and key design patterns used.
4. **Implementation**: Provide detailed steps, code snippets, and configurations.
5. **Milestones**: Outline the key milestones for tracking progress.
6. **Gathering Results**: Explain how to evaluate the success of the implementation.

Let's start by outlining each section.

```asciidoc
= SPEC-1: User Registration, Login with JWT Authentication, and Logout with Spring Security
:sectnums:
:toc:

== Background

This document outlines the design and implementation of a user registration, login, and logout system using Spring Security with JWT (JSON Web Token) for authentication and authorization. The goal is to create a secure, maintainable, and scalable solution by separating concerns into different layers and components.

== Requirements

*Functional Requirements*:
- Must have user registration with validation (Must)
- Must provide JWT-based login (Must)
- Must support logout functionality (Must)
- Should validate JWT for protected routes (Should)
- Should refresh JWT tokens (Should)
- Could provide role-based access control (Could)

*Non-Functional Requirements*:
- Must ensure security best practices (Must)
- Should have clear separation of concerns (Should)
- Should be scalable and maintainable (Should)

== Method

=== Architecture

The architecture will follow the layered approach:

1. **Controller Layer**: Handles HTTP requests and responses.
2. **Service Layer**: Contains business logic.
3. **Repository Layer**: Interacts with the database.
4. **Security Layer**: Manages authentication and authorization using filters and JWT.

[plantuml]
@startuml
package "Controller Layer" {
    class AuthController
}

package "Service Layer" {
    class UserService
    class AuthService
}

package "Repository Layer" {
    class UserRepository
}

package "Security Layer" {
    class JwtRequestFilter
    class JwtAuthenticationEntryPoint
    class JwtTokenProvider
    class CustomUserDetailsService
}

AuthController --> AuthService
AuthService --> UserService
UserService --> UserRepository
JwtRequestFilter --> JwtTokenProvider
JwtTokenProvider --> CustomUserDetailsService
@enduml

=== Component Design

* **AuthController**: Handles registration and login requests.
* **UserService**: Manages user-related operations.
* **AuthService**: Handles authentication and token generation.
* **UserRepository**: Interacts with the database for user CRUD operations.
* **JwtRequestFilter**: Filters incoming requests to validate JWT.
* **JwtAuthenticationEntryPoint**: Handles unauthorized access.
* **JwtTokenProvider**: Generates and validates JWT.
* **CustomUserDetailsService**: Loads user-specific data.

== Implementation

Let's start with the implementation of each component.

=== User Entity

```java
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private String roles; // Comma-separated roles

    // Getters and setters
}
```

=== UserRepository

```java
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
```

=== UserService

```java
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public User saveUser(User user) {
        user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
        return userRepository.save(user);
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
```

=== AuthService

```java
@Service
public class AuthService {
    @Autowired
    private UserService userService;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private AuthenticationManager authenticationManager;

    public String login(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        User user = userService.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return jwtTokenProvider.createToken(username, user.getRoles());
    }

    public User register(User user) {
        return userService.saveUser(user);
    }
}
```

=== AuthController

```java
@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        User registeredUser = authService.register(user);
        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        String token = authService.login(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(new AuthResponse(token));
    }
}

@Data
class AuthRequest {
    private String username;
    private String password;
}

@Data
@AllArgsConstructor
class AuthResponse {
    private String token;
}
```

=== JwtTokenProvider

```java
@Component
public class JwtTokenProvider {
    @Value("${security.jwt.token.secret-key:secret}")
    private String secretKey;
    private final long validityInMilliseconds = 3600000; // 1h

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String createToken(String username, String roles) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidJwtAuthenticationException("Expired or invalid JWT token");
        }
    }
}
```

=== JwtRequestFilter

```java
@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = resolveToken(request);
        if (token != null && jwtTokenProvider.validateToken(token)) {
            String username = jwtTokenProvider.getUsername(token);
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

=== JwtAuthenticationEntryPoint

```java
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) 
            throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}
```

=== CustomUserDetailsService

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), getAuthorities(user));
    }

    private Collection<? extends GrantedAuthority> getAuthorities(User user) {
        return Arrays.stream(user.getRoles().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
```

=== Security Configuration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private JwtRequestFilter jwtRequestFilter;
    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/auth/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws

 Exception {
        auth.userDetailsService(customUserDetailsService()).passwordEncoder(new BCryptPasswordEncoder());
    }

    @Bean
    public AuthenticationManager customAuthenticationManager() throws Exception {
        return authenticationManagerBean();
    }

    @Bean
    public UserDetailsService customUserDetailsService() {
        return new CustomUserDetailsService();
    }
}
```

== Milestones

1. **Milestone 1**: Define user entity and repository.
2. **Milestone 2**: Implement user registration and login logic.
3. **Milestone 3**: Create JWT token provider.
4. **Milestone 4**: Set up JWT request filter and authentication entry point.
5. **Milestone 5**: Configure Spring Security.
6. **Milestone 6**: Perform integration testing.

== Gathering Results

To evaluate the success of this implementation, we will:
- Verify user registration and login functionality through integration tests.
- Ensure JWT tokens are generated and validated correctly.
- Test protected routes to confirm authorization.
- Review security best practices compliance.
- Gather feedback from initial users and perform load testing for scalability.
```

This document outlines a comprehensive plan for implementing user registration, login with JWT authentication and authorization, and logout functionality using Spring Security, with clear separation of concerns and adherence to security best practices. Each step includes code snippets and configuration examples for clarity.

