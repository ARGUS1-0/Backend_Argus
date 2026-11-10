package org.acme.domain.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "notification_logs")
public class NotificationLog {
    public enum DeliveryStatus { PENDING_RETRY, DELIVERED, FAILED }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Integer id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "vulnerability_id", nullable = false)
    public Vulnerability vulnerability;

    @Column(nullable = false, length = 100)
    public String destination;

    @Enumerated(EnumType.STRING)
    @Column(name = "delivery_status", nullable = false, length = 16)
    public DeliveryStatus deliveryStatus;

    @Column(name = "provider_response", columnDefinition = "text")
    public String providerResponse;

    @Column(name = "dispatched_at", insertable = false, updatable = false)
    public LocalDateTime dispatchedAt;
}