## Spring Boot Security Project

Here’s a suggested section for downloading the code from GitHub, which you can include in your document:

---

## Downloading the Code from GitHub

To access the complete implementation of the discussed topics, you can download the code from our GitHub repository. Follow these steps to get started:

### Step 1: Access the GitHub Repository

1. Open your web browser and navigate to the following URL:
   - [GitHub Repository Link](https://github.com/DineshSripathi718?tab=repositories)

### Step 2: Clone the Repository

You can clone the repository to your local machine using Git. Open your terminal or command prompt and run the following command:

```bash
git clone https://github.com/SpringSecurityExample
```

### Step 3: Navigate to the Project Directory

After cloning the repository, navigate to the project directory:

```bash
cd Repo-name
```

### Step 4: Explore the Code

You can now explore the code files and folders in your local directory. The implementation of the JwtFilter, JwtService, and other components discussed in this document are located in the appropriate directories.

### Additional Resources

- For detailed instructions on how to run the project, refer to the **README.md** file in the repository.
- If you encounter any issues or have questions, feel free to open an issue in the repository or contact us for support.


## Overview

In every application, security is essential to keep data secure. In Spring Boot, we provide security using **Spring Security**. This document will walk you through setting up Spring Security, handling user authentication and authorization, and managing CSRF tokens.


| **Table of Contents**                     |
|--------------------------------------------|
| **1. JwtFilter Class Implementation**      |
| - Overview of JwtFilter Class              |
| - Setting Request Object in upaToken       |
| - Updating Security Context with Authentication |
| - Moving to the Next Filter in the Filter Chain |
| **2. Verifying Username and Validating Token in JwtService** |
| - Extracting Username from JWT              |
| - Extracting Claims from JWT                |
| - Validating JWT Token                      |
| - Checking Token Expiration                 |
| **3. Logging Through Third-Party Apps**    |
| - Overview of Third-Party Authentication    |
| - Dependencies for Third-Party Authentication |
| - Creating a Controller for OAuth2 Authentication |
| - Configuring GitHub as an OAuth2 Provider  |
| - Setting Up Application Properties for GitHub |
| **4. Security Configuration for OAuth2**   |
| - Enabling OAuth2 Login                     |
| - Configuring SecurityFilterChain for OAuth2 |


## Creating a Spring Boot Security Project

To start a Spring Boot project with security enabled, follow these steps:

1. **Create a Spring Starter Project** using Spring Initializr or your preferred method.
2. **Add Dependencies**:
    - Spring Web
    - Spring Dev Tools (optional)
    - Database Driver (e.g., MySQL, H2)
    - Spring Data JPA
    - Spring Security

3. **Create a REST Controller**:
   - By default, Spring Security will generate a login form, and the default password can be found in the console.
   - **Username**: `user`  
   - **Password**: Found in the console output during application startup.

   Example:
   ```
   Login: localhost:8080/login
   Logout: localhost:8080/logout
   ```

To change the password for a single user, set it in the `application.properties` file.

---

## Working of Spring Security

Spring Security ensures that all requests to the server are authenticated and authorized. It works by using filters to process the request and response from the client.

- **Authentication**: Confirms that the user is who they claim to be.
- **Authorization**: Determines if the authenticated user has permission to access certain resources.

Spring Security filters can be customized based on your needs.

**Note**: Each time you log in, a new session ID is created to ensure different users have unique session IDs.

---

## Changing the Username and Password

To change the default username and password, configure the `UsernamePasswordAuthenticationFilter` in your `application.properties` file.

```properties
spring.security.user.name = yourUsername
spring.security.user.password = yourPassword
```

Once configured, the new username and password will be used for login.

---

## Connecting with Postman

When connecting Spring Boot Security with Postman, authentication is required. Otherwise, a `401 Unauthorized` error will occur. Follow these steps:

1. Go to the **Authorization** tab in Postman.
2. Select **Basic Auth**.
3. Enter the username and password in the respective fields.

Now Postman will authenticate successfully and allow you to interact with your secured application.

---

## CSRF (Cross-Site Request Forgery) Token

### What is CSRF?

CSRF is an attack where an attacker tricks the client browser into sending an unintended request to a verified server (e.g., a banking site) without the user’s knowledge, leading to unauthorized actions.

To mitigate this, Spring Security uses **CSRF tokens** for state-changing operations like `POST`, `PUT`, and `DELETE`.

### Handling CSRF Tokens

Whenever you want to perform operations that modify data, you need to handle CSRF tokens. Spring generates this token automatically for such operations.

**How to retrieve the CSRF token:**

1. Use the following method in your controller to get the CSRF token:
   ```java
   @GetMapping("/getCSRFToken")
   public CsrfToken getCsrfToken(HttpServletRequest request) {
       return (CsrfToken) request.getAttribute("_csrf");
   }
   ```

2. Access the endpoint `/getCSRFToken` via Postman or the browser to retrieve the CSRF token.

### Using CSRF Tokens in Postman

When sending `POST`, `PUT`, or `DELETE` requests, you need to include the CSRF token in the request headers.

1. Go to the **Headers** section in Postman.
2. Add the following key-value pair:
   ```text
   X-CSRF-TOKEN: yourTokenValue
   ```

Now, Postman will be able to process the request with the correct CSRF token.

---

**Note**: While you can fetch the CSRF token manually each time, it’s recommended to generate a session-based CSRF token automatically for a smoother user experience.

Here's an organized explanation for configuring security in Spring Boot using **Spring Security**, with steps for setting up user authentication, connecting with Postman, and managing CSRF tokens:

---

### **Setting Up Spring Boot Security**

1. **Create a Spring Starter Project**:
   - Add dependencies:
     - `Spring Web`
     - `Spring Security`
     - `Spring JPA`
     - `Database Driver` (e.g., MySQL)
     - (Optional) `Spring Dev Tools`

2. **Create a REST Controller**:
   - Spring Boot will generate a default login form, and the password will be printed in the console. The default username is `user`.

---

### **Changing Username and Password**

To set a custom username and password, configure the `application.properties` file:
```properties
spring.security.user.name = customUser
spring.security.user.password = customPassword
```

---

### **Working with Postman for Authentication**

1. **Status 401 (Unauthorized)**:
   - You will receive a `401 Unauthorized` if no authorization is provided.
   
2. **Authorize Using Basic Auth**:
   - Go to the Authorization section in Postman.
   - Select **Basic Auth**.
   - Enter your username and password to connect.

---

### **Cross-Site Request Forgery (CSRF) Protection**

1. **What is CSRF?**
   - An attack where an attacker tricks a logged-in user to submit unintended requests.

2. **Handling CSRF in Spring**:
   - By default, Spring Security asks for a CSRF token for POST, PUT, and DELETE requests.
   - Use the following code to retrieve the CSRF token:
   ```java
   @GetMapping("/getCSRFToken")
   public CsrfToken getCsrfToken(HttpServletRequest request) {
       return (CsrfToken) request.getAttribute("_csrf");
   }
   ```

3. **Using CSRF Token in Postman**:
   - Get the CSRF token and include it in the header of your Postman request:
   ```http
   X-CSRF-TOKEN: yourTokenValue
   ```

---

### **Spring Security Configuration**

1. **Basic Setup**:
   - Create a configuration class with `@Configuration` and `@EnableWebSecurity` annotations.
   - Define a `SecurityFilterChain` bean to configure security filters.
   ```java
   @Configuration
   @EnableWebSecurity
   public class SecurityConfiguration {
       @Bean
       public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
           return httpSecurity.build();
       }
   }
   ```

2. **Disable CSRF (Using Lambda Expression)**:
   ```java
   httpSecurity.csrf(customizer -> customizer.disable());
   ```

3. **Enable Authentication**:
   ```java
   httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated());
   ```

4. **Login Form**:
   ```java
   httpSecurity.formLogin(Customizer.withDefaults());
   ```

5. **Enable Login for APIs (Basic Authentication)**:
   ```java
   httpSecurity.httpBasic(Customizer.withDefaults());
   ```

6. **Stateless Sessions** (Create new session for every request):
   ```java
   httpSecurity.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
   ```

7. **Chaining Security Methods**:
   ```java
   httpSecurity.csrf(customizer -> customizer.disable())
       .authorizeHttpRequests(request -> request.anyRequest().authenticated())
       .formLogin(Customizer.withDefaults())
       .httpBasic(Customizer.withDefaults())
       .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
   ```

---

### **User Authentication from Database**

1. **Create a `UserDetailsService` Bean**:
   - This service will manage the user credentials.
   ```java
   @Bean
   public UserDetailsService userDetails() {
       UserDetails user1 = User.withDefaultPasswordEncoder()
               .username("Ravi")
               .password("ravi")
               .roles("admin", "trainer")
               .build();
       return new InMemoryUserDetailsManager(user1);
   }
   ```

2. **Connect to the Database for Authentication**:
   - Use `DaoAuthenticationProvider` to connect to a database.
   - Create a custom `UserDetailsService` class that retrieves users from the database.

   ```java
   @Autowired
   private DatabaseUserDetailsService userDetailsService;

   @Bean
   public AuthenticationProvider authenticationProvider() {
       DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
       daoProvider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
       daoProvider.setUserDetailsService(userDetailsService);
       return daoProvider;
   }
   ```

---
Here's an organized explanation for configuring security in Spring Boot using **Spring Security**, with steps for setting up user authentication, connecting with Postman, and managing CSRF tokens:

---

### **Setting Up Spring Boot Security**

1. **Create a Spring Starter Project**:
   - Add dependencies:
     - `Spring Web`
     - `Spring Security`
     - `Spring JPA`
     - `Database Driver` (e.g., MySQL)
     - (Optional) `Spring Dev Tools`

2. **Create a REST Controller**:
   - Spring Boot will generate a default login form, and the password will be printed in the console. The default username is `user`.

---

### **Changing Username and Password**

To set a custom username and password, configure the `application.properties` file:
```properties
spring.security.user.name = customUser
spring.security.user.password = customPassword
```

---

### **Working with Postman for Authentication**

1. **Status 401 (Unauthorized)**:
   - You will receive a `401 Unauthorized` if no authorization is provided.
   
2. **Authorize Using Basic Auth**:
   - Go to the Authorization section in Postman.
   - Select **Basic Auth**.
   - Enter your username and password to connect.

---

### **Cross-Site Request Forgery (CSRF) Protection**

1. **What is CSRF?**
   - An attack where an attacker tricks a logged-in user to submit unintended requests.

2. **Handling CSRF in Spring**:
   - By default, Spring Security asks for a CSRF token for POST, PUT, and DELETE requests.
   - Use the following code to retrieve the CSRF token:
   ```java
   @GetMapping("/getCSRFToken")
   public CsrfToken getCsrfToken(HttpServletRequest request) {
       return (CsrfToken) request.getAttribute("_csrf");
   }
   ```

3. **Using CSRF Token in Postman**:
   - Get the CSRF token and include it in the header of your Postman request:
   ```http
   X-CSRF-TOKEN: yourTokenValue
   ```

---

### **Spring Security Configuration**

1. **Basic Setup**:
   - Create a configuration class with `@Configuration` and `@EnableWebSecurity` annotations.
   - Define a `SecurityFilterChain` bean to configure security filters.
   ```java
   @Configuration
   @EnableWebSecurity
   public class SecurityConfiguration {
       @Bean
       public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
           return httpSecurity.build();
       }
   }
   ```

2. **Disable CSRF (Using Lambda Expression)**:
   ```java
   httpSecurity.csrf(customizer -> customizer.disable());
   ```

3. **Enable Authentication**:
   ```java
   httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated());
   ```

4. **Login Form**:
   ```java
   httpSecurity.formLogin(Customizer.withDefaults());
   ```

5. **Enable Login for APIs (Basic Authentication)**:
   ```java
   httpSecurity.httpBasic(Customizer.withDefaults());
   ```

6. **Stateless Sessions** (Create new session for every request):
   ```java
   httpSecurity.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
   ```

7. **Chaining Security Methods**:
   ```java
   httpSecurity.csrf(customizer -> customizer.disable())
       .authorizeHttpRequests(request -> request.anyRequest().authenticated())
       .formLogin(Customizer.withDefaults())
       .httpBasic(Customizer.withDefaults())
       .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
   ```

---

### **User Authentication from Database**

1. **Create a `UserDetailsService` Bean**:
   - This service will manage the user credentials.
   ```java
   @Bean
   public UserDetailsService userDetails() {
       UserDetails user1 = User.withDefaultPasswordEncoder()
               .username("Ravi")
               .password("ravi")
               .roles("admin", "trainer")
               .build();
       return new InMemoryUserDetailsManager(user1);
   }
   ```

2. **Connect to the Database for Authentication**:
   - Use `DaoAuthenticationProvider` to connect to a database.
   - Create a custom `UserDetailsService` class that retrieves users from the database.

   ```java
   @Autowired
   private DatabaseUserDetailsService userDetailsService;

   @Bean
   public AuthenticationProvider authenticationProvider() {
       DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
       daoProvider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
       daoProvider.setUserDetailsService(userDetailsService);
       return daoProvider;
   }
   ```
This detailed guide walks through configuring Spring Security and incorporating various security features such as CSRF protection, authentication, password encryption, database integration, and JWT usage. Let's break down key elements from this configuration:

### 1. **Configuring Spring Security**:
   - **Create a security configuration class** using `@Configuration` and `@EnableWebSecurity`.
   - Define a `SecurityFilterChain` bean that configures various filters (CSRF, authentication, etc.) using the `HttpSecurity` object.
   - **Example**:

   ```java
   @Configuration
   @EnableWebSecurity
   public class SecurityConfiguration {
       @Bean
       public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
           return httpSecurity.csrf(csrf -> csrf.disable())
                               .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                               .formLogin(Customizer.withDefaults())
                               .httpBasic(Customizer.withDefaults())
                               .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                               .build();
       }
   }
   ```

### 2. **CSRF Protection**:
   - **Disabling CSRF** with or without lambda expressions.
   - **Example**:

   ```java
   httpSecurity.csrf(csrf -> csrf.disable());
   ```

### 3. **Enabling Authentication**:
   - Activate authentication for all requests using `authorizeHttpRequests`.
   - **Example**:

   ```java
   httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated());
   ```

### 4. **Login Forms**:
   - Enable login forms in the browser and REST APIs (e.g., Postman).
   - **Examples**:

   ```java
   httpSecurity.formLogin(Customizer.withDefaults());  // Browser login
   httpSecurity.httpBasic(Customizer.withDefaults());  // REST API login
   ```

### 5. **Session Management**:
   - Manage sessions by making them stateless to generate new session IDs for each request.
   - **Example**:

   ```java
   httpSecurity.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
   ```

### 6. **Custom UserDetailsService**:
   - When dealing with multiple users, create a `UserDetailsService` to manage users from a database. Spring Security uses `UserDetailsService` for loading user-specific data during authentication.
   - **Example** of `UserDetailsService` implementation:

   ```java
   @Service
   public class DatabaseUserDetailsService implements UserDetailsService {
       @Autowired
       UsersDao usersDao;

       @Override
       public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
           Users user = usersDao.getByName(username);
           if (user == null) {
               throw new UsernameNotFoundException("User not found");
           }
           return new UserPrincipal(user);
       }
   }
   ```

### 7. **UserPrincipal Class**:
   - Create a `UserPrincipal` class to represent the authenticated user's details.
   - **Example**:

   ```java
   public class UserPrincipal implements UserDetails {
       private Users user;

       public UserPrincipal(Users user) {
           this.user = user;
       }

       @Override
       public Collection<? extends GrantedAuthority> getAuthorities() {
           return List.of(new SimpleGrantedAuthority(user.getRole()));
       }

       @Override
       public String getPassword() {
           return user.getPassword();
       }

       @Override
       public String getUsername() {
           return user.getUsername();
       }
   }
   ```

### 8. **Encrypting Passwords with BCrypt**:
   - Encrypt passwords using BCryptPasswordEncoder, which applies hashing to user passwords before storing them in the database.
   - **Example** of password encryption during user registration:

   ```java
   public Users registerUser(Users user) {
       BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);
       user.setPassword(passwordEncoder.encode(user.getPassword()));
       return userDao.save(user);
   }
   ```

   - When authenticating, ensure that Spring Security also uses `BCryptPasswordEncoder`:
   - **Example** of updating authentication provider:

   ```java
   @Bean
   public AuthenticationProvider getAuthentication() {
       DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
       provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
       provider.setUserDetailsService(userDetailsService);
       return provider;
   }
   ```

### 9. **Using JWT for Authentication**:
   - JWT is used to authenticate users by issuing a token after login, which includes encoded data and an expiry duration.
   - The JWT is passed along with every request after login, providing stateless authentication.
   - **JWT Integration** involves generating tokens, verifying tokens, and attaching them to the response header for secure communication.

### 10. **Entity Class for Users**:
   - **Example** of `Users` entity class mapped to the database table:

   ```java
   @Entity
   public class Users {
       @Id
       private Integer id;
       private String name;
       private String password;
       private String role;
   }
   ```
To implement JWT in a Spring project, follow these steps:

### 1. **Add Dependencies**
- Search for and add the following dependencies in your `pom.xml` (Maven project):
  - `jjwt-api`
  - `jjwt-impl`
  - `jjwt-jackson`

### 2. **Configure `AuthenticationManager`**
In the `SecurityConfiguration` class, create a bean for `AuthenticationManager`:
```java
@Bean
public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
    return authConfig.getAuthenticationManager();
}
```

### 3. **Create JWT Utility and Service**
#### JWT Utility for token generation and validation:

```java
@Service
public class JwtService {
    
    private SecretKey key;
    
    public JwtService() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            this.key = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    
    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000)) // 1 hour expiration
                .signWith(key)
                .compact();
    }
    
    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
    
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    
    private boolean isTokenExpired(String token) {
        Date expiration = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        return expiration.before(new Date());
    }
}
```

### 4. **Custom JWT Filter**
Create a custom filter to validate JWT tokens:

```java
public class JwtAuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String jwtToken = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwtToken = authHeader.substring(7);
            username = jwtService.extractUsername(jwtToken);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (jwtService.validateToken(jwtToken, userDetails)) {
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

### 5. **Update Spring Security Configuration**
In your `SecurityConfiguration` class, add the JWT filter and configure security settings:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthTokenFilter jwtAuthTokenFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/register", "/loginUser", "/home").permitAll()
                .anyRequest().authenticated())
            .addFilterBefore(jwtAuthTokenFilter, UsernamePasswordAuthenticationFilter.class)
            .httpBasic(Customizer.withDefaults());
        
        return http.build();
    }
}
```

### 6. **Authentication and Token Generation in Service**
In your service class, authenticate the user and generate a token if authentication is successful:

```java
@Service
public class AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    public String authenticateUser(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password));
        
        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(username);
        } else {
            throw new RuntimeException("Invalid credentials");
        }
    }
}
```

### 7. **Verify Token in Requests**
Whenever a client makes a request with the token, the `JwtAuthTokenFilter` ensures the token is valid and the user is authenticated.

### 8. **Error Handling**
Use the `AuthEntryPointJwt` class to handle unauthorized access attempts.
This content explains the implementation of JWT (JSON Web Token) authentication using Spring Security and integrating third-party OAuth2 login (e.g., GitHub) into a Spring application.

### JWT Authentication

1. **JWT Filter Class**:
   The `JwtFilter` class is responsible for intercepting requests, extracting JWT tokens from the `Authorization` header, and validating the token to authenticate users.

   Key Steps:
   - Extract the JWT token from the request header.
   - Validate the JWT and ensure it matches the user in the system.
   - If valid, associate the user with a `UsernamePasswordAuthenticationToken` and set it in the `SecurityContextHolder`.
   - Move to the next filter using `filterChain.doFilter(request, response)`.

2. **JwtService Class**:
   This class handles the core JWT functionality:
   - Generating JWT tokens with claims (like `username`) and setting expiration.
   - Extracting and validating the JWT, including checking the expiration date.
   - Using a secret key for token signing and validation.

   Key Methods:
   - `generateToken(String username)`: Creates the JWT.
   - `extractUsername(String jwtToken)`: Extracts the username from the token.
   - `validateToken(String jwtToken, UserDetails userDetails)`: Verifies if the token is valid and not expired.
   - `extractClaim()` and `extractAllClaims()`: Helper methods to get specific claims (like expiration, username) from the JWT.

3. **Key Concepts**:
   - **SecurityContextHolder**: Stores security details (authentication) during the request lifecycle.
   - **UsernamePasswordAuthenticationToken**: Used to authenticate the user if the token is valid.
   - **WebAuthenticationDetails**: Associates the request details with the authentication token.

### OAuth2 Login with GitHub Example

1. **Spring Security OAuth2 Configuration**:
   OAuth2 login allows users to authenticate using third-party services like GitHub.
   - Add required dependencies like `OAuth2Client`.
   - Configure the `application.properties` with `client-id` and `client-secret` obtained from GitHub Developer Settings.
   - Use `oauth2Login()` in the `SecurityFilterChain` configuration to enable OAuth2-based authentication.

   Example OAuth2 configuration in `SecurityFilterChain`:
   ```java
   @Bean
   public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
       return httpSecurity.csrf(csrf -> csrf.disable())
           .authorizeHttpRequests(auth -> auth
               .requestMatchers("/register", "/loginUser", "/homepage").permitAll()
               .anyRequest().authenticated())
           .oauth2Login(Customizer.withDefaults()) // GitHub OAuth2 login
           .formLogin(Customizer.withDefaults()) // Default form login
           .httpBasic(Customizer.withDefaults()) // Basic authentication
           .build();
   }
   ```

2. **GitHub OAuth2 Properties**:
   Add client registration details in `application.properties`:
   ```properties
   spring.security.oauth2.client.registration.github.client-id=your-client-id
   spring.security.oauth2.client.registration.github.client-secret=your-client-secret
   ```

3. **GitHub OAuth App Setup**:
   - In GitHub Developer Settings, create a new OAuth app.
   - Configure fields like `Application Name`, `Homepage URL`, and `Authorization Callback URL`.
   - After creating the app, use the provided `client-id` and `client-secret` for Spring Security OAuth2 configuration.

