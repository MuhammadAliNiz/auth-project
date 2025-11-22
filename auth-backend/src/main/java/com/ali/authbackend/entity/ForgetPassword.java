package com.ali.authbackend.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(indexes = {
        @Index(name = "idx_reset_token", columnList = "resetToken"),
        @Index(name = "idx_user_id", columnList = "user_id")
})
public class ForgetPassword {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "userId", nullable = false, unique = true)
    private User user;

    @Column(nullable = false, unique = true)
    private String resetToken;

    @Column(nullable = false)
    @Builder.Default
    private Boolean used = false;

    @Column(nullable = false)
    private Instant expirationDate;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;
}