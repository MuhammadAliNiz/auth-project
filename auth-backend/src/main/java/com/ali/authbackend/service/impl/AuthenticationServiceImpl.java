package com.ali.authbackend.service.impl;

import com.ali.authbackend.dto.request.EmailVerificationRequest;
import com.ali.authbackend.dto.request.LoginRequest;
import com.ali.authbackend.dto.request.RegisterRequest;
import com.ali.authbackend.dto.request.ResetPasswordRequest;
import com.ali.authbackend.dto.response.AuthResponse;
import com.ali.authbackend.entity.ForgetPassword;
import com.ali.authbackend.entity.RefreshToken;
import com.ali.authbackend.entity.User;
import com.ali.authbackend.entity.enums.RolesEnum;
import com.ali.authbackend.exception.InvalidRefreshTokenException;
import com.ali.authbackend.exception.RefreshTokenNotFoundException;
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
import java.util.List;
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
    public void sendForgotPasswordEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User with email " + email + " not found"));

        //delete forget password row if exists
        forgetPasswordRepository.findByUserEmail(email)
                .ifPresent(forgetPasswordRepository::delete);

        String resetToken = UUID.randomUUID().toString();

        ForgetPassword forgetPassword = ForgetPassword.builder()
                .user(user)
                .resetToken(resetToken)
                .used(false)
                .expirationDate(Instant.now().plus(15, ChronoUnit.MINUTES))
                .build();

        forgetPasswordRepository.save(forgetPassword);

        emailService.sendForgetPasswordEmail(
                user.getEmail(),
                user.getFirstName(),
                resetToken
        );

        log.info("Password reset email sent to: {}", email);
    }


    @Override
    public boolean validateResetToken(String token) {
        return forgetPasswordRepository
                .findByResetTokenAndUsedFalseAndExpirationDateAfter(token, Instant.now())
                .isPresent();
    }

    @Transactional
    @Override
    public void resetPassword(ResetPasswordRequest request) {
        ForgetPassword forgetPassword = forgetPasswordRepository
                .findByResetTokenAndUsedFalseAndExpirationDateAfter(request.getToken(), Instant.now())
                .orElseThrow(() -> new RuntimeException("Invalid or expired reset token"));

        User user = forgetPassword.getUser();

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        forgetPassword.setUsed(true);
        forgetPasswordRepository.save(forgetPassword);

        user.revokeAllRefreshTokens();

        log.info("Password reset successfully for user: {}", user.getEmail());
    }

    @Transactional
    @Override
    public AuthResponse refreshToken(
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse) {

        String refreshToken = cookieUtils.extractCookieValue(httpServletRequest, "refresh-token")
                .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh token cookie not found"));

        if (jwtTokenProvider.validateToken(refreshToken)) {

            String jti = jwtTokenProvider.getTokenIdFromToken(refreshToken);
            String userEmail = jwtTokenProvider.getEmailFromToken(refreshToken);

            User user = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new UserNotFoundException("User not found"));

            RefreshToken storedRefreshToken = refreshTokenRepository.findByJtiAndUser(jti, user)
                    .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh token not found"));

            if (storedRefreshToken.isRevoked() || storedRefreshToken.getExpiryDate().isBefore(Instant.now())) {
                log.info("Refresh token is revoked or expired for user: {}", user.getEmail());
                throw new InvalidRefreshTokenException("Invalid refresh token");
            }

            // Update last used time
            storedRefreshToken.setLastUsedAt(Instant.now());
            refreshTokenRepository.save(storedRefreshToken);

            String newAccessToken = jwtTokenProvider.generateAccessToken(user);

            AuthResponse response = new AuthResponse();

            response.setUserId(user.getUserId());
            response.setEmail(user.getEmail());
            response.setEmailVerified(user.isEmailVerified());
            response.setFirstName(user.getFirstName());
            response.setLastName(user.getLastName());
            response.setAccessToken(newAccessToken);

            log.info("Access token refreshed successfully for user: {}", user.getEmail());

            return response;
        }
        throw  new InvalidRefreshTokenException("Invalid refresh token");
    }

    @Transactional
    public void logout() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        List<RefreshToken> activeTokens = refreshTokenRepository.findAllByUserAndRevokedFalse(user);
        activeTokens.forEach(RefreshToken::revoke);
        refreshTokenRepository.saveAll(activeTokens);

        log.info("User logged out successfully: {}", email);
    }

    private String generateVerificationCode() {
        SecureRandom secureRandom = new SecureRandom();
        return String.format("%06d", secureRandom.nextInt(1000000));
    }


}
