package com.ali.authbackend.service;

public interface EmailService {
    void sendVerificationEmail(String toEmail, String userName, String verificationCode);
    void sendWelcomeEmail(String toEmail, String userName);
    void sendPasswordResetEmail(String toEmail, String userName, String resetToken);
    void sendLoginAlert(String email, String firstName, String ipAddress, String deviceInfo, String location);

}
