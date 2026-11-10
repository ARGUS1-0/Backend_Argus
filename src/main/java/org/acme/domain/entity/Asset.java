package org.acme.domain.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.Set;

@Entity
@Table(name = "lyft_assets")
public class Asset {
    public enum Criticality { LOW, MEDIUM, HIGH, CRITICAL }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Integer id;

    @Column(nullable = false, length = 100)
    public String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    public Criticality criticality;

    @Column(name = "responsible_team", nullable = false, length = 100)
    public String responsibleTeam;

    @Column(name = "created_at", insertable = false, updatable = false)
    public LocalDateTime createdAt;

    @OneToMany(mappedBy = "asset", cascade = CascadeType.ALL, orphanRemoval = true)
    public Set<AssetIp> ipAddresses = new LinkedHashSet<>();

    @ManyToMany(mappedBy = "assets")
    public Set<Vulnerability> vulnerabilities = new LinkedHashSet<>();
}