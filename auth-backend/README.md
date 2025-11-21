# Spring Boot AOP (Aspect-Oriented Programming) Tutorial

Complete guide to understanding and implementing AOP in Spring Boot applications.

---

## 📚 Table of Contents

- [What is AOP?](#what-is-aop)
- [Core AOP Concepts](#core-aop-concepts)
- [Getting Started](#getting-started)
- [Basic Implementation](#basic-implementation)
- [Advice Types](#advice-types)
- [Pointcut Expressions](#pointcut-expressions)
- [Real-World Examples](#real-world-examples)
- [Best Practices](#best-practices)
- [Common Use Cases](#common-use-cases)
- [Troubleshooting](#troubleshooting)

---

## What is AOP?

**Aspect-Oriented Programming (AOP)** is a programming paradigm that allows you to modularize cross-cutting concerns (features that affect multiple parts of your application).

### Cross-Cutting Concerns Examples:
- 🔒 **Security** - Authentication & Authorization
- 📊 **Logging** - Method entry/exit, parameters
- ⏱️ **Performance Monitoring** - Execution time tracking
- 🔄 **Transaction Management** - Database transactions
- 🛡️ **Error Handling** - Exception handling
- ✅ **Validation** - Input validation
- 📝 **Auditing** - Track changes

### Why Use AOP?

```java
// ❌ WITHOUT AOP - Repetitive code everywhere
public String getUser(Long id) {
    log.info("Getting user with id: {}", id);
    long start = System.currentTimeMillis();
    
    String user = userRepository.findById(id);
    
    long end = System.currentTimeMillis();
    log.info("Execution time: {} ms", (end - start));
    return user;
}

// ✅ WITH AOP - Clean, focused code
public String getUser(Long id) {
    return userRepository.findById(id);
}
```

---

## Core AOP Concepts

### 1. **Aspect**
A module that encapsulates cross-cutting concerns.

```java
@Aspect
@Component
public class LoggingAspect {
    // Contains advice methods
}
```

### 2. **Join Point**
A point during program execution (method execution, exception thrown, etc.)

### 3. **Advice**
Action taken at a particular join point (before, after, around, etc.)

### 4. **Pointcut**
An expression that matches join points where advice should be applied.

```java
@Before("execution(* com.example.service.*.*(..))")
```

### 5. **Weaving**
The process of linking aspects with other application types or objects.

---

## Getting Started

### 1. Add Dependencies

```xml
<dependencies>
    <!-- Spring Boot Starter AOP -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-aop</artifactId>
    </dependency>
    
    <!-- Spring Boot Starter Web (for REST APIs) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- Lombok (Optional - for cleaner code) -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>
```

### 2. Enable AOP (Optional - Auto-configured in Spring Boot)

```java
@SpringBootApplication
@EnableAspectJAutoProxy
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

---

## Basic Implementation

### Simple Logging Aspect

```java
package com.example.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component
public class LoggingAspect {

    // Executes BEFORE method execution
    @Before("execution(* com.example.service.*.*(..))")
    public void logBefore(JoinPoint joinPoint) {
        log.info("Executing: {}", joinPoint.getSignature().getName());
    }

    // Executes AFTER method execution
    @After("execution(* com.example.service.*.*(..))")
    public void logAfter(JoinPoint joinPoint) {
        log.info("Completed: {}", joinPoint.getSignature().getName());
    }
}
```

### Sample Service

```java
package com.example.service;

import org.springframework.stereotype.Service;

@Service
public class UserService {

    public String getUser(Long id) {
        return "User-" + id;
    }

    public void createUser(String name) {
        System.out.println("Creating user: " + name);
    }
}
```

### Output
```
INFO : Executing: getUser
User-1
INFO : Completed: getUser
```

---

## Advice Types

### 1. **@Before** - Execute Before Method

```java
@Before("execution(* com.example.service.*.*(..))")
public void beforeAdvice(JoinPoint joinPoint) {
    log.info("Before method: {}", joinPoint.getSignature().getName());
    log.info("Arguments: {}", Arrays.toString(joinPoint.getArgs()));
}
```

**Use Cases:**
- Validation
- Security checks
- Logging method entry

---

### 2. **@After** - Execute After Method (Always)

```java
@After("execution(* com.example.service.*.*(..))")
public void afterAdvice(JoinPoint joinPoint) {
    log.info("After method execution (success or exception)");
}
```

**Use Cases:**
- Cleanup operations
- Resource release
- Logging completion

---

### 3. **@AfterReturning** - Execute After Successful Return

```java
@AfterReturning(
    pointcut = "execution(* com.example.service.*.*(..))",
    returning = "result"
)
public void afterReturningAdvice(JoinPoint joinPoint, Object result) {
    log.info("Method {} returned: {}", 
             joinPoint.getSignature().getName(), 
             result);
}
```

**Use Cases:**
- Result transformation
- Success logging
- Post-processing

---

### 4. **@AfterThrowing** - Execute After Exception

```java
@AfterThrowing(
    pointcut = "execution(* com.example.service.*.*(..))",
    throwing = "error"
)
public void afterThrowingAdvice(JoinPoint joinPoint, Throwable error) {
    log.error("Method {} threw exception: {}", 
              joinPoint.getSignature().getName(), 
              error.getMessage());
}
```

**Use Cases:**
- Error logging
- Exception notification
- Rollback operations

---

### 5. **@Around** - Most Powerful (Wrap Method Execution)

```java
@Around("execution(* com.example.service.*.*(..))")
public Object aroundAdvice(ProceedingJoinPoint joinPoint) throws Throwable {
    long start = System.currentTimeMillis();
    
    log.info("Method {} starting...", joinPoint.getSignature().getName());
    
    Object result = null;
    try {
        // Execute the actual method
        result = joinPoint.proceed();
        return result;
    } catch (Exception e) {
        log.error("Exception in method: {}", e.getMessage());
        throw e;
    } finally {
        long end = System.currentTimeMillis();
        log.info("Method {} completed in {} ms", 
                 joinPoint.getSignature().getName(), 
                 (end - start));
    }
}
```

**Use Cases:**
- Performance monitoring
- Caching
- Transaction management
- Retry logic

---

## Pointcut Expressions

### Basic Syntax

```
execution([modifiers] return-type [package].class.method(parameters) [throws exceptions])
```

### Common Patterns

```java
// 1. All methods in a specific package
@Before("execution(* com.example.service.*.*(..))")

// 2. Specific method
@Before("execution(* com.example.service.UserService.getUser(..))")

// 3. Methods returning specific type
@Before("execution(String com.example.service.*.*(..))")

// 4. Methods with specific parameters
@Before("execution(* com.example.service.*.*(Long, String))")

// 5. Methods with any number of parameters
@Before("execution(* com.example.service.*.*(..))")

// 6. Public methods only
@Before("execution(public * com.example.service.*.*(..))")

// 7. Methods starting with 'get'
@Before("execution(* com.example.service.*.get*(..))")

// 8. All methods in package and sub-packages
@Before("execution(* com.example.service..*.*(..))")
```

### Reusable Pointcuts

```java
@Aspect
@Component
public class CommonPointcuts {

    @Pointcut("execution(* com.example.service.*.*(..))")
    public void serviceMethods() {}

    @Pointcut("execution(* com.example.controller.*.*(..))")
    public void controllerMethods() {}

    @Pointcut("@annotation(com.example.annotation.Loggable)")
    public void loggableMethods() {}

    @Pointcut("within(com.example.service..*)")
    public void inServiceLayer() {}
}
```

**Usage:**

```java
@Aspect
@Component
public class LoggingAspect {

    @Before("CommonPointcuts.serviceMethods()")
    public void logServiceMethods(JoinPoint joinPoint) {
        log.info("Service method called: {}", joinPoint.getSignature().getName());
    }
}
```

---

## Real-World Examples

### 1. Performance Monitoring

```java
package com.example.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component
public class PerformanceAspect {

    @Around("execution(* com.example.service..*.*(..))")
    public Object measureExecutionTime(ProceedingJoinPoint joinPoint) throws Throwable {
        long start = System.currentTimeMillis();
        
        String className = joinPoint.getSignature().getDeclaringTypeName();
        String methodName = joinPoint.getSignature().getName();
        
        Object result = joinPoint.proceed();
        
        long executionTime = System.currentTimeMillis() - start;
        
        log.info("{}:{} executed in {} ms", 
                 className, methodName, executionTime);
        
        if (executionTime > 3000) {
            log.warn("SLOW METHOD DETECTED: {}:{} took {} ms", 
                     className, methodName, executionTime);
        }
        
        return result;
    }
}
```

---

### 2. Method Parameter & Return Value Logging

```java
package com.example.aspect;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class DetailedLoggingAspect {

    private final ObjectMapper objectMapper;

    @Before("execution(* com.example.controller..*.*(..))")
    public void logMethodEntry(JoinPoint joinPoint) {
        String methodName = joinPoint.getSignature().getName();
        Object[] args = joinPoint.getArgs();
        
        try {
            String argsJson = objectMapper.writeValueAsString(args);
            log.info("→ Entering method: {} with arguments: {}", methodName, argsJson);
        } catch (Exception e) {
            log.info("→ Entering method: {} with arguments: {}", methodName, args);
        }
    }

    @AfterReturning(
        pointcut = "execution(* com.example.controller..*.*(..))",
        returning = "result"
    )
    public void logMethodExit(JoinPoint joinPoint, Object result) {
        String methodName = joinPoint.getSignature().getName();
        
        try {
            String resultJson = objectMapper.writeValueAsString(result);
            log.info("← Exiting method: {} with result: {}", methodName, resultJson);
        } catch (Exception e) {
            log.info("← Exiting method: {} with result: {}", methodName, result);
        }
    }
}
```

---

### 3. Exception Handling & Notification

```java
package com.example.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Arrays;

@Slf4j
@Aspect
@Component
public class ExceptionHandlingAspect {

    @AfterThrowing(
        pointcut = "execution(* com.example.service..*.*(..))",
        throwing = "exception"
    )
    public void handleException(JoinPoint joinPoint, Exception exception) {
        String methodName = joinPoint.getSignature().toShortString();
        String args = Arrays.toString(joinPoint.getArgs());
        
        log.error("❌ Exception in method: {}", methodName);
        log.error("   Arguments: {}", args);
        log.error("   Exception: {}", exception.getMessage());
        log.error("   Timestamp: {}", LocalDateTime.now());
        
        // Send notification (email, Slack, etc.)
        sendAlertNotification(methodName, exception);
    }

    private void sendAlertNotification(String methodName, Exception exception) {
        // Implementation for sending alerts
        log.warn("📧 Alert sent for exception in: {}", methodName);
    }
}
```

---

### 4. Custom Annotation-Based AOP

#### Create Custom Annotation

```java
package com.example.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface TrackExecutionTime {
    String value() default "";
}
```

#### Create Aspect

```java
package com.example.aspect;

import com.example.annotation.TrackExecutionTime;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component
public class TrackExecutionTimeAspect {

    @Around("@annotation(com.example.annotation.TrackExecutionTime)")
    public Object trackTime(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        TrackExecutionTime annotation = signature.getMethod()
            .getAnnotation(TrackExecutionTime.class);
        
        String label = annotation.value().isEmpty() 
            ? signature.getName() 
            : annotation.value();
        
        long start = System.currentTimeMillis();
        Object result = joinPoint.proceed();
        long executionTime = System.currentTimeMillis() - start;
        
        log.info("⏱️ [{}] executed in {} ms", label, executionTime);
        
        return result;
    }
}
```

#### Usage

```java
@Service
public class UserService {

    @TrackExecutionTime("Get User Operation")
    public User getUser(Long id) {
        // Method implementation
        return userRepository.findById(id);
    }

    @TrackExecutionTime
    public void createUser(User user) {
        // Method implementation
        userRepository.save(user);
    }
}
```

---

### 5. Security & Authorization

```java
package com.example.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component
public class SecurityAspect {

    @Before("@annotation(com.example.annotation.RequiresAdmin)")
    public void checkAdminAccess(JoinPoint joinPoint) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (auth == null || !auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            
            log.warn("Unauthorized access attempt to: {}", 
                     joinPoint.getSignature().getName());
            throw new SecurityException("Admin access required");
        }
        
        log.info("Admin access granted to: {} for method: {}", 
                 auth.getName(), 
                 joinPoint.getSignature().getName());
    }
}
```

---

### 6. Caching with AOP

```java
package com.example.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Aspect
@Component
public class CachingAspect {

    private final Map<String, Object> cache = new ConcurrentHashMap<>();

    @Around("@annotation(com.example.annotation.Cacheable)")
    public Object cacheResult(ProceedingJoinPoint joinPoint) throws Throwable {
        String key = generateKey(joinPoint);
        
        if (cache.containsKey(key)) {
            log.info("Cache HIT for key: {}", key);
            return cache.get(key);
        }
        
        log.info("Cache MISS for key: {}", key);
        Object result = joinPoint.proceed();
        cache.put(key, result);
        
        return result;
    }

    private String generateKey(ProceedingJoinPoint joinPoint) {
        StringBuilder key = new StringBuilder();
        key.append(joinPoint.getSignature().toShortString());
        
        for (Object arg : joinPoint.getArgs()) {
            key.append(":").append(arg);
        }
        
        return key.toString();
    }
}
```

---

### 7. Retry Logic

```java
package com.example.aspect;

import com.example.annotation.Retry;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component
public class RetryAspect {

    @Around("@annotation(com.example.annotation.Retry)")
    public Object retry(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Retry retry = signature.getMethod().getAnnotation(Retry.class);
        
        int maxAttempts = retry.maxAttempts();
        long delay = retry.delay();
        
        Throwable lastException = null;
        
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                log.info("Attempt {}/{} for method: {}", 
                         attempt, maxAttempts, signature.getName());
                return joinPoint.proceed();
            } catch (Exception e) {
                lastException = e;
                log.warn("Attempt {}/{} failed: {}", 
                         attempt, maxAttempts, e.getMessage());
                
                if (attempt < maxAttempts) {
                    Thread.sleep(delay);
                }
            }
        }
        
        log.error("All {} attempts failed for method: {}", 
                  maxAttempts, signature.getName());
        throw lastException;
    }
}
```

**Retry Annotation:**

```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Retry {
    int maxAttempts() default 3;
    long delay() default 1000; // milliseconds
}
```

**Usage:**

```java
@Service
public class ExternalApiService {

    @Retry(maxAttempts = 3, delay = 2000)
    public String callExternalApi() {
        // API call that might fail
        return restTemplate.getForObject("https://api.example.com/data", String.class);
    }
}
```

---

### 8. Audit Logging

```java
package com.example.aspect;

import com.example.entity.AuditLog;
import com.example.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class AuditAspect {

    private final AuditLogRepository auditLogRepository;

    @AfterReturning(
        pointcut = "@annotation(com.example.annotation.Audited)",
        returning = "result"
    )
    public void auditMethod(JoinPoint joinPoint, Object result) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : "anonymous";
        
        AuditLog auditLog = AuditLog.builder()
            .username(username)
            .methodName(joinPoint.getSignature().toShortString())
            .arguments(joinPoint.getArgs())
            .result(result)
            .timestamp(LocalDateTime.now())
            .build();
        
        auditLogRepository.save(auditLog);
        log.info("Audit log created for method: {} by user: {}", 
                 joinPoint.getSignature().getName(), username);
    }
}
```

---

## Best Practices

### 1. ✅ Keep Aspects Focused

```java
// ✅ Good - Single responsibility
@Aspect
@Component
public class LoggingAspect {
    // Only logging logic
}

@Aspect
@Component
public class PerformanceAspect {
    // Only performance monitoring
}

// ❌ Bad - Too many responsibilities
@Aspect
@Component
public class EverythingAspect {
    // Logging, performance, security, caching...
}
```

### 2. ✅ Use Specific Pointcuts

```java
// ✅ Good - Specific
@Before("execution(* com.example.service.UserService.createUser(..))")

// ❌ Bad - Too broad
@Before("execution(* *(..))")
```

### 3. ✅ Handle Exceptions Properly

```java
@Around("execution(* com.example.service..*.*(..))")
public Object around(ProceedingJoinPoint joinPoint) throws Throwable {
    try {
        return joinPoint.proceed();
    } catch (Exception e) {
        log.error("Exception in aspect", e);
        throw e; // Always re-throw
    }
}
```

### 4. ✅ Use @Order for Multiple Aspects

```java
@Aspect
@Component
@Order(1) // Executes first
public class SecurityAspect { }

@Aspect
@Component
@Order(2) // Executes second
public class LoggingAspect { }
```

### 5. ✅ Extract Reusable Pointcuts

```java
@Aspect
@Component
public class CommonPointcuts {
    
    @Pointcut("execution(* com.example.service..*.*(..))")
    public void serviceLayer() {}
    
    @Pointcut("execution(* com.example.controller..*.*(..))")
    public void controllerLayer() {}
}
```

### 6. ✅ Use Conditional Aspects

```java
@Aspect
@Component
@ConditionalOnProperty(name = "app.aop.logging.enabled", havingValue = "true")
public class LoggingAspect {
    // Only active when property is true
}
```

---

## Common Use Cases

| Use Case | Advice Type | Example |
|----------|-------------|---------|
| **Logging** | @Before, @After | Method entry/exit logging |
| **Performance** | @Around | Execution time measurement |
| **Security** | @Before | Authorization checks |
| **Caching** | @Around | Result caching |
| **Transaction** | @Around | Transaction management |
| **Exception Handling** | @AfterThrowing | Error logging & notifications |
| **Audit** | @AfterReturning | User action tracking |
| **Validation** | @Before | Input validation |
| **Retry** | @Around | Retry failed operations |
| **Rate Limiting** | @Before | Request throttling |

---

## Troubleshooting

### Issue 1: Aspect Not Executing

**Problem:** Aspect doesn't execute on methods.

**Solutions:**
```java
// ✅ Ensure @Aspect and @Component are present
@Aspect
@Component
public class MyAspect { }

// ✅ Check pointcut expression syntax
@Before("execution(* com.example.service.*.*(..))")

// ✅ Ensure Spring Boot AOP is enabled (auto-configured by default)
@EnableAspectJAutoProxy
```

### Issue 2: Private Methods Not Working

**Problem:** AOP doesn't work on private methods.

**Solution:** AOP only works on public methods called from outside the class.

```java
// ❌ Won't work
private void privateMethod() { }

// ✅ Will work
public void publicMethod() { }
```

### Issue 3: Self-Invocation Not Working

**Problem:** AOP doesn't work when calling method from same class.

```java
@Service
public class UserService {
    
    public void methodA() {
        methodB(); // ❌ AOP won't apply
    }
    
    @Transactional
    public void methodB() { }
}
```

**Solution:** Use dependency injection:

```java
@Service
@RequiredArgsConstructor
public class UserService {
    
    private final UserService self; // Inject self
    
    public void methodA() {
        self.methodB(); // ✅ AOP will apply
    }
    
    @Transactional
    public void methodB() { }
}
```

### Issue 4: Performance Impact

**Problem:** Too many aspects slow down application.

**Solutions:**
- Use specific pointcuts (avoid broad patterns)
- Disable aspects in development if not needed
- Use @ConditionalOnProperty for optional aspects

---

## Complete Example Project

```java
// Application.java
@SpringBootApplication
public class AopDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(AopDemoApplication.class, args);
    }
}

// UserController.java
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
    
    private final UserService userService;
    
    @GetMapping("/{id}")
    public User getUser(@PathVariable Long id) {
        return userService.getUser(id);
    }
    
    @PostMapping
    public User createUser(@RequestBody User user) {
        return userService.createUser(user);
    }
}

// UserService.java
@Service
public class UserService {
    
    @TrackExecutionTime("Get User")
    public User getUser(Long id) {
        // Simulate processing
        return new User(id, "User-" + id);
    }
    
    @TrackExecutionTime("Create User")
    @Audited
    public User createUser(User user) {
        // Simulate saving
        return user;
    }
}

// LoggingAspect.java (as shown in examples above)
// PerformanceAspect.java (as shown in examples above)
// AuditAspect.java (as shown in examples above)
```

---

## 🎓 Summary

### When to Use AOP:

✅ **Cross-cutting concerns** affecting multiple parts  
✅ **Avoid code duplication** (logging, security, etc.)  
✅ **Separation of concerns** (keep business logic clean)  
✅ **Centralized configuration** (easier maintenance)

### When NOT to Use AOP:

❌ Simple, one-off operations  
❌ Core business logic  
❌ When debugging becomes difficult  
❌ When performance is critical

---

## Resources

- [Spring AOP Documentation](https://docs.spring.io/spring-framework/docs/current/reference/html/core.html#aop)
- [AspectJ Documentation](https://www.eclipse.org/aspectj/doc/released/progguide/index.html)
- [Baeldung AOP Tutorial](https://www.baeldung.com/spring-aop)

---

**Author:** Nawab Hallar  
**Date:** 2025-11-16  
**Version:** 1.0.0

---

Happy coding with Spring Boot AOP! 🚀