package com.ali.authbackend.service.impl;

import com.ali.authbackend.service.EmailService;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${app.name}")
    private String appName;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    @Value("${app.backend-url}")
    private String backendUrl;

    @Value("${app.mail.from}")
    private String fromEmailAddress;

    @Value("{app.mail.from-name}")
    private String fromEmailName;

    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
                    .withZone(ZoneId.of("UTC"));

    @Override
    @Async
    public void sendVerificationEmail(String toEmail, String userName, String verificationCode) {
        try {
            log.info("Sending verification email to: {}", toEmail);

            Context context = new Context();
            context.setVariable("userName", userName);
            context.setVariable("verificationCode", verificationCode);
            context.setVariable("appName", appName);

            String htmlContent = templateEngine.process("email-verification", context);

            sendEmail(
                    toEmail,
                    "Email Verification - " + appName,
                    htmlContent
            );

            log.info("Verification email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send verification email to {}", toEmail, e);
            throw new RuntimeException("Failed to send verification email", e);
        }
    }

    @Override
    @Async
    public void sendWelcomeEmail(String toEmail, String userName) {
        try {
            log.info("Sending welcome email to: {}", toEmail);

            Context context = new Context();
            context.setVariable("userName", userName);
            context.setVariable("appName", appName);
            context.setVariable("dashboardUrl", frontendUrl + "/dashboard");

            String htmlContent = templateEngine.process("welcome-email", context);

            sendEmail(
                    toEmail,
                    "Welcome to " + appName + "!",
                    htmlContent
            );

            log.info("Welcome email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send welcome email to {}", toEmail, e);
            throw new RuntimeException("Failed to send welcome email", e);
        }
    }

    @Override
    @Async
    public void sendPasswordResetEmail(String toEmail, String userName, String resetToken) {
        try {
            log.info("Sending password reset email to: {}", toEmail);

            String resetLink = backendUrl +
                    "/pages/reset-password-page?token=" + resetToken;

            Context context = new Context();
            context.setVariable("userName", userName);
            context.setVariable("resetLink", resetLink);
            context.setVariable("appName", appName);

            String htmlContent = templateEngine.process("password-reset", context);

            sendEmail(
                    toEmail,
                    "Password Reset Request - " + appName,
                    htmlContent
            );

            log.info("Password reset email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send password reset email to {}", toEmail, e);
            throw new RuntimeException("Failed to send password reset email", e);
        }
    }

    @Override
    @Async
    public void sendLoginAlert(String email, String firstName, String ipAddress, String deviceInfo, String location) {
        try {
            log.info("Sending login alert to: {}", email);

            String loginTime = DATE_TIME_FORMATTER.format(Instant.now());

            Context context = new Context();
            context.setVariable("firstName", firstName);
            context.setVariable("ipAddress", ipAddress != null ? ipAddress : "Unknown");
            context.setVariable("device", deviceInfo != null ? deviceInfo : "Unknown Device");
            context.setVariable("location", location != null ? location : "Unknown Location");
            context.setVariable("loginTime", loginTime);
            context.setVariable("appName", appName);

            String htmlContent = templateEngine.process("login-alert", context);

            sendEmail(
                    email,
                    "New Login Alert - " + appName,
                    htmlContent
            );

            log.info("Login alert sent successfully to: {}", email);
        } catch (Exception e) {
            log.error("Failed to send login alert to {}", email, e);
            // Don't throw exception for login alerts to not block the login process
        }
    }

    @Override
    @Async
    public void sendForgetPasswordEmail(String email, String firstName, String resetToken) {
        try {
            log.info("Sending forget password email to: {}", email);

            String resetLink = backendUrl +
                    "/pages/reset-password-page?token=" + resetToken;

            Context context = new Context();
            context.setVariable("firstName", firstName);
            context.setVariable("resetLink", resetLink);
            context.setVariable("appName", appName);

            String htmlContent = templateEngine.process("forget-password-email", context);

            sendEmail(
                    email,
                    "Password Reset - " + appName,
                    htmlContent
            );

            log.info("Forget password email sent successfully to: {}", email);
        } catch (Exception e) {
            log.error("Failed to send forget password email to {}", email, e);
            throw new RuntimeException("Failed to send forget password email", e);
        }
    }

    /**
     * Private helper method to send email using JavaMailSender
     */
    private void sendEmail(String to, String subject, String htmlContent) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(
                    fromEmailAddress,
                    fromEmailName
            );
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(message);

            log.debug("Email sent successfully - To: {}, Subject: {}", to, subject);
        } catch (Exception e) {
            log.error("Failed to send email - To: {}, Subject: {}", to, subject, e);
            throw new RuntimeException("Failed to send email", e);
        }
    }
}