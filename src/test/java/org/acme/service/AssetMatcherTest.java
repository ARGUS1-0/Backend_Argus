package org.acme.service;

import org.acme.domain.entity.Asset;
import org.acme.domain.entity.AssetIp;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.acme.service.NessusFinding.AssetResolution.*;
import static org.junit.jupiter.api.Assertions.*;

class AssetMatcherTest {
    private static final String ARGUS1 = "10.128.0.10";

    private final Asset redis = asset("Redis Sesiones – Transporte");
    private final Asset mongo = asset("MongoDB – CRM");
    private final Asset mysql = asset("MySQL – ERP");
    private final Asset vm = asset("VM argus1");

    /** Inventario típico de argus1: varios contenedores en la misma IP, diferenciados por puerto. */
    private final List<AssetIp> argus1 = List.of(
            row(redis, 6379), row(mongo, 27017), row(mysql, 3306));

    @Test
    void sharedIpIsResolvedByPort() {
        assertMatched(redis, AssetMatcher.match(argus1, 6379));
        assertMatched(mongo, AssetMatcher.match(argus1, 27017));
        assertMatched(mysql, AssetMatcher.match(argus1, 3306));
    }

    @Test
    void unregisteredPortOnSharedIpIsNotFoundInsteadOfGuessing() {
        AssetMatcher.Match match = AssetMatcher.match(argus1, 22);
        assertEquals(NOT_FOUND, match.resolution());
        assertNull(match.asset());
    }

    @Test
    void wholeHostAssetCatchesPortsWithoutSpecificOwner() {
        List<AssetIp> rows = List.of(row(redis, 6379), row(vm, null));

        assertMatched(redis, AssetMatcher.match(rows, 6379), "Exact port wins over whole-host");
        assertMatched(vm, AssetMatcher.match(rows, 22));
        assertMatched(vm, AssetMatcher.match(rows, 0), "Host-level finding (port 0)");
        assertMatched(vm, AssetMatcher.match(rows, null));
    }

    @Test
    void hostLevelFindingWithOnlyPortSpecificAssetsIsNotFound() {
        assertEquals(NOT_FOUND, AssetMatcher.match(argus1, 0).resolution());
    }

    @Test
    void legacyRowsWithoutPortStillMatchSingleOwner() {
        assertMatched(redis, AssetMatcher.match(List.of(row(redis, null)), 6379));
    }

    @Test
    void contradictoryInventoryIsAmbiguous() {
        AssetMatcher.Match match = AssetMatcher.match(List.of(row(redis, null), row(mongo, null)), 6379);
        assertEquals(AMBIGUOUS, match.resolution());
        assertNull(match.asset());
    }

    @Test
    void sameAssetRegisteredTwiceIsNotAmbiguous() {
        assertMatched(redis, AssetMatcher.match(List.of(row(redis, null), row(redis, 6379)), 6379));
    }

    @Test
    void unknownIpIsNotFound() {
        assertEquals(NOT_FOUND, AssetMatcher.match(null, 6379).resolution());
        assertEquals(NOT_FOUND, AssetMatcher.match(List.of(), 6379).resolution());
    }

    private static void assertMatched(Asset expected, AssetMatcher.Match match) {
        assertMatched(expected, match, null);
    }

    private static void assertMatched(Asset expected, AssetMatcher.Match match, String message) {
        assertEquals(MATCHED, match.resolution(), message);
        assertSame(expected, match.asset(), message);
    }

    private static Asset asset(String name) {
        Asset asset = new Asset();
        asset.name = name;
        return asset;
    }

    private static AssetIp row(Asset asset, Integer port) {
        AssetIp ip = new AssetIp();
        ip.asset = asset;
        ip.ipAddress = ARGUS1;
        ip.port = port;
        return ip;
    }
}
