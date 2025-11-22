package com.ali.authbackend.service.impl;

import com.ali.authbackend.service.EmailService;
import jakarta.mail.MessagingException;
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

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${app.mail.from}")
    private String fromEmail;

    @Value("${app.mail.from-name}")
    private String fromName;

    @Async
    @Override
    public void sendVerificationEmail(String toEmail, String userName, String verificationCode) {
        try {
            Context context = new Context();
            context.setVariable("userName", userName);
            context.setVariable("verificationCode", verificationCode);

            String htmlContent = templateEngine.process("email-verification", context);

            sendHtmlEmail(toEmail, "Verify Your Email Address", htmlContent);
            log.info("Verification email sent successfully to: {}", toEmail);
        } catch (MessagingException | UnsupportedEncodingException e) {
            log.error("Failed to send verification email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send verification email", e);
        }
    }

    @Async
    @Override
    public void sendWelcomeEmail(String toEmail, String userName) {
        try {
            Context context = new Context();
            context.setVariable("userName", userName);

            String htmlContent = templateEngine.process("welcome-email", context);

            sendHtmlEmail(toEmail, "Welcome to YourApp!", htmlContent);
            log.info("Welcome email sent successfully to: {}", toEmail);
        } catch (MessagingException | UnsupportedEncodingException e) {
            log.error("Failed to send welcome email to: {}", toEmail, e);
        }
    }

    @Async
    @Override
    public void sendLoginAlert(String email, String firstName, String ipAddress, String deviceInfo, String location) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(email);
            helper.setSubject("Security Alert: New Login to Your Account");
            helper.setFrom(fromEmail);

            Context context = new Context();
            context.setVariable("firstName", firstName);
            context.setVariable("loginTime", Instant.now().toString());
            context.setVariable("ipAddress", ipAddress);
            context.setVariable("device", deviceInfo != null ? deviceInfo : "Unknown Device");
            context.setVariable("location", location != null ? location : "Unknown Location");

            String htmlContent = templateEngine.process("login-alert", context);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Login alert email sent to: {}", email);
        } catch (MessagingException e) {
            log.error("Failed to send login alert email to: {}", email, e);
            throw new RuntimeException("Failed to send login alert email", e);
        }
    }


    @Async
    @Override
    public void sendPasswordResetEmail(String toEmail, String userName, String resetToken) {
        try {
            Context context = new Context();
            context.setVariable("userName", userName);
            context.setVariable("resetToken", resetToken);
            context.setVariable("resetLink", "http://localhost:3000/reset-password?token=" + resetToken);

            String htmlContent = templateEngine.process("password-reset", context);

            sendHtmlEmail(toEmail, "Reset Your Password", htmlContent);
            log.info("Password reset email sent successfully to: {}", toEmail);
        } catch (MessagingException | UnsupportedEncodingException e) {
            log.error("Failed to send password reset email to: {}", toEmail, e);
        }
    }


    @Async
    @Override
    public void sendForgetPasswordEmail(String email, String firstName, String resetToken) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(email);
            helper.setSubject("Reset Your Password");

            Context context = new Context();
            context.setVariable("firstName", firstName);
            context.setVariable("resetToken", resetToken);

            String htmlContent = templateEngine.process("forget-password-email", context);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Forget password email sent successfully to: {}", email);
        } catch (MessagingException e) {
            log.error("Failed to send forget password email to: {}", email, e);
            throw new RuntimeException("Failed to send forget password email", e);
        }
    }


    private void sendHtmlEmail(String to, String subject, String htmlContent)
            throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(
                message,
                MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED,
                StandardCharsets.UTF_8.name()
        );

        helper.setFrom(fromEmail, fromName);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);

        mailSender.send(message);
    }
}