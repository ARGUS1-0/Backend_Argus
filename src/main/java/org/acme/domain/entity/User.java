package org.acme.domain.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class User {
    public enum Role { SOC_ANALYST, SOC_MANAGER, SYS_ADMIN }

    @Id
    @Column(name = "firebase_uid", length = 128, nullable = false)
    public String firebaseUid;

    @Column(nullable = false, unique = true, length = 255)
    public String email;

    @Column(name = "full_name", nullable = false, length = 150)
    public String fullName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    public Role role = Role.SOC_ANALYST;

    @Column(name = "created_at", insertable = false, updatable = false)
    public LocalDateTime createdAt;
}
