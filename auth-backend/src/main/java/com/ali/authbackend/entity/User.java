package com.ali.authbackend.entity;

import com.ali.authbackend.entity.enums.RolesEnum;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.*;
import org.hibernate.annotations.BatchSize;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Getter
@Setter
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email"),
        @Index(name = "idx_user_created_at", columnList = "createdAt"),
        @Index(name = "idx_user_verification_code", columnList = "emailVerificationCode")
})
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID userId;

    @Column(length = 100)
    private String firstName;

    @Column(length = 100)
    private String lastName;

    @Email(message = "Email must be valid")
    @Column(nullable = false, unique = true)
    private String email;

    private String emailVerificationCode;

    private Instant expiryEmailVerificationCodeTime;

    @Column(nullable = false)
    @Builder.Default
    private boolean emailVerified = false;

    @Column(nullable = false)
    private String password;

    @Column(length = 512)
    private String profileImageUrl;

    private boolean isEnabled = true;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id", foreignKey = @ForeignKey(name = "fk_user_roles_user"))
    )
    @Column(name = "role_name", nullable = false)
    @BatchSize(size = 25)
    @Builder.Default
    private Set<RolesEnum> roles = new HashSet<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @BatchSize(size = 10)
    @Builder.Default
    private List<RefreshToken> refreshTokens = new ArrayList<>();

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (roles == null || roles.isEmpty()) {
            return Collections.emptyList();
        }

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .collect(Collectors.toSet());
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }


    public void addRole(RolesEnum role) {
        if (this.roles == null) {
            this.roles = new HashSet<>();
        }
        this.roles.add(role);
    }

    public void removeRole(RolesEnum role) {
        if (this.roles != null) {
            this.roles.remove(role);
        }
    }

    public boolean hasRole(RolesEnum role) {
        return this.roles != null && this.roles.contains(role);
    }

    public boolean isAdmin() {
        return hasRole(RolesEnum.ROLE_ADMIN);
    }

    public void addRefreshToken(RefreshToken token) {
        if (this.refreshTokens == null) {
            this.refreshTokens = new ArrayList<>();
        }
        refreshTokens.add(token);
        token.setUser(this);
    }

    public void revokeAllRefreshTokens() {
        if (this.refreshTokens != null) {
            refreshTokens.forEach(token -> token.setRevoked(true));
        }
    }

}