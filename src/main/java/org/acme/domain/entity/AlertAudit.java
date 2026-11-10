package org.acme.domain.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "alert_audits")
public class AlertAudit {
    public enum ActionTaken { MARKED_AS_FALSE_POSITIVE, ESCALATED_TO_JIRA, SEVERITY_CHANGED }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Integer id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "vulnerability_id", nullable = false)
    public Vulnerability vulnerability;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_uid", referencedColumnName = "firebase_uid", nullable = false)
    public User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "action_taken", nullable = false, length = 32)
    public ActionTaken actionTaken;

    @Column(nullable = false, columnDefinition = "text")
    public String justification;

    @Column(name = "reviewed_at", insertable = false, updatable = false)
    public LocalDateTime reviewedAt;
}
