package com.ali.authbackend.service.impl;

import com.ali.authbackend.dto.request.EmailVerificationRequest;
import com.ali.authbackend.dto.request.LoginRequest;
import com.ali.authbackend.dto.request.RegisterRequest;
import com.ali.authbackend.dto.response.AuthResponse;
import com.ali.authbackend.entity.ForgetPassword;
import com.ali.authbackend.entity.RefreshToken;
import com.ali.authbackend.entity.User;
import com.ali.authbackend.entity.enums.RolesEnum;
import com.ali.authbackend.exception.ResourceAlreadyExistsException;
import com.ali.authbackend.exception.UserNotFoundException;
import com.ali.authbackend.repository.ForgetPasswordRepository;
import com.ali.authbackend.repository.RefreshTokenRepository;
import com.ali.authbackend.repository.UserRepository;
import com.ali.authbackend.security.jwt.JwtTokenProvider;
import com.ali.authbackend.service.AuthenticationService;
import com.ali.authbackend.service.EmailService;
import com.ali.authbackend.util.CookieUtils;
import com.ali.authbackend.util.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final CookieUtils cookieUtils;
    private final PasswordEncoder passwordEncoder;
    private final SecurityUtils securityUtils;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;
    private final ForgetPasswordRepository forgetPasswordRepository;


    @Value("${app.jwt.refresh-expiration-ms}")
    private long refreshTokenExpirationMs;

    @Override
    public boolean checkEmailAvailability(String email) {
        return !userRepository.existsByEmail(email);
    }

    @Transactional
    @Override
    public AuthResponse register(RegisterRequest registerRequest, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {

        log.info("Registering user with email {}", registerRequest.getEmail());

        if(userRepository.existsByEmail(registerRequest.getEmail())){
            log.info("User with email {} already exists", registerRequest.getEmail());
            throw new ResourceAlreadyExistsException("User with email " + registerRequest.getEmail() + " already exists");
        }

        User user = new User();

        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setRoles(Set.of(RolesEnum.ROLE_USER));

        String verificationCode = generateVerificationCode();

        user.setEmailVerificationCode(verificationCode);
        user.setExpiryEmailVerificationCodeTime(Instant.now().plus(15, ChronoUnit.MINUTES));

        User savedUser = userRepository.save(user);

        emailService.sendVerificationEmail(
                savedUser.getEmail(),
                savedUser.getFirstName(),
                verificationCode
        );

        String accessToken = jwtTokenProvider.generateAccessToken(savedUser);

        AuthResponse response = new AuthResponse();

        response.setUserId(savedUser.getUserId());
        response.setEmail(savedUser.getEmail());
        response.setEmailVerified(savedUser.isEmailVerified());
        response.setFirstName(savedUser.getFirstName());
        response.setLastName(savedUser.getLastName());
        response.setAccessToken(accessToken);

        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setJti(UUID.randomUUID().toString());
        refreshToken.setUser(savedUser);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpirationMs));
        refreshToken.setRevoked(false);
        refreshToken.setLastUsedAt(Instant.now());
        refreshToken.setDeviceInfo(httpServletRequest.getHeader("User-Agent"));
        refreshToken.setIpAddress(httpServletRequest.getRemoteAddr());

        RefreshToken savedToken = refreshTokenRepository.save(refreshToken);

        String refreshTokenJwt = jwtTokenProvider.generateRefreshToken(savedUser, savedToken.getJti());

        ResponseCookie refreshTokenCookie = cookieUtils.createHttpOnlyCookie("refresh-token", refreshTokenJwt, refreshTokenExpirationMs/1000);

        httpServletResponse.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        log.info("User {} registered successfully", savedUser.getEmail());


        return response;
    }

    @Transactional
    @Override
    public void resendVerificationEmail() {
        User user = securityUtils.getCurrentUser()
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        String verificationCode = generateVerificationCode();

        user.setEmailVerificationCode(verificationCode);
        user.setExpiryEmailVerificationCodeTime(Instant.now().plus(15, ChronoUnit.MINUTES));

        User savedUser = userRepository.save(user);

        emailService.sendVerificationEmail(
                savedUser.getEmail(),
                savedUser.getFirstName(),
                verificationCode
        );

        log.info("Verification email sent successfully to: {}", user.getEmail());

    }

    @Transactional
    @Override
    public boolean verifyEmail(EmailVerificationRequest emailVerificationRequest) {

        User user = securityUtils.getCurrentUser()
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (user.isEmailVerified()) {
            log.info("Email is already verified: {}", user.getEmail() );
            throw new ResourceAlreadyExistsException("Email is already verified");
        }

        if (user.getEmailVerificationCode().equals(emailVerificationRequest.getCode())
        && Instant.now().isBefore(user.getExpiryEmailVerificationCodeTime())) {

            user.setEmailVerified(true);
            userRepository.save(user);

            emailService.sendWelcomeEmail(user.getEmail(), user.getFirstName());

            return true;
        }
        return false;
    }

    @Transactional
    @Override
    public AuthResponse login(
            LoginRequest loginRequest,
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse) {

        log.info("Login attempt for email: {}", loginRequest.getEmail());

        Authentication authentication;

        try{
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );
        }catch (BadCredentialsException e){
            log.info("Invalid credentials for email: {}", loginRequest.getEmail());
            throw new BadCredentialsException("Invalid email or password");
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = (User) authentication.getPrincipal();

        log.info("User {} logged in successfully", user.getEmail());
        log.info("Email verified: {}", user.isEmailVerified());

        String accessToken = jwtTokenProvider.generateAccessToken(user);

        String ipAddress = httpServletRequest.getRemoteAddr();
        String deviceInfo = httpServletRequest.getHeader("User-Agent");

        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setJti(UUID.randomUUID().toString());
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpirationMs));
        refreshToken.setRevoked(false);
        refreshToken.setLastUsedAt(Instant.now());
        refreshToken.setDeviceInfo(deviceInfo);
        refreshToken.setIpAddress(ipAddress);

        RefreshToken savedToken = refreshTokenRepository.save(refreshToken);

        String refreshTokenJwt = jwtTokenProvider.generateRefreshToken(user, savedToken.getJti());

        ResponseCookie refreshTokenCookie = cookieUtils.createHttpOnlyCookie(
                "refresh-token",
                refreshTokenJwt,
                refreshTokenExpirationMs / 1000
        );

        httpServletResponse.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());


        // Send login alert email
        emailService.sendLoginAlert(
                user.getEmail(),
                user.getFirstName(),
                ipAddress,
                deviceInfo,
                "Unknown" // You can integrate IP geolocation service for actual location
        );

        AuthResponse response = new AuthResponse();

        response.setUserId(user.getUserId());
        response.setEmail(user.getEmail());
        response.setEmailVerified(user.isEmailVerified());
        response.setFirstName(user.getFirstName());
        response.setLastName(user.getLastName());
        response.setAccessToken(accessToken);

        log.info("User {} logged in successfully", user.getEmail());

        return response;
    }

    @Override
    public boolean sendForgotPasswordEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User with email " + email + " not found"));

        ForgetPassword forgetPassword = new ForgetPassword();

        forgetPassword.setUser(user);
        forgetPassword.setResetToken(generateVerificationCode());
        forgetPassword.setExpirationDate(Instant.now().plus(15, ChronoUnit.MINUTES));

        ForgetPassword savedForgetPassword = forgetPasswordRepository.save(forgetPassword);

        emailService.sendForgetPasswordEmail(
                user.getEmail(),
                user.getFirstName(),
                savedForgetPassword.getResetToken()
        );


        return true;
    }

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private String generateVerificationCode() {
        return String.format("%06d", SECURE_RANDOM.nextInt(1000000));
    }


}
