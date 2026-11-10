package org.acme.service;

import org.acme.domain.entity.Asset;
import org.acme.domain.entity.AssetIp;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Decide a qué activo pertenece un hallazgo a partir de las filas de asset_ips de su IP.
 *
 * <ol>
 *   <li>Coincidencia exacta IP + puerto: gana siempre (Redis 6379, Mongo 27017... en argus1).</li>
 *   <li>Si no hay, un activo registrado para todo el host ({@code port = null}).</li>
 *   <li>Si la IP está registrada solo con otros puertos: NOT_FOUND. El servicio no está inventariado,
 *       y no se adivina el dueño solo porque comparte IP.</li>
 * </ol>
 * Solo queda AMBIGUOUS si el inventario mismo es contradictorio (dos activos distintos en el mismo nivel).
 */
final class AssetMatcher {
    record Match(NessusFinding.AssetResolution resolution, Asset asset) {
    }

    private AssetMatcher() {
    }

    /** @param candidates filas de asset_ips con la misma IP del hallazgo */
    static Match match(Collection<AssetIp> candidates, Integer findingPort) {
        if (candidates == null || candidates.isEmpty()) return notFound();

        Integer port = findingPort == null || findingPort <= 0 ? null : findingPort;
        if (port != null) {
            List<Asset> exact = distinctAssets(candidates.stream()
                    .filter(ip -> port.equals(ip.port)).toList());
            if (!exact.isEmpty()) return resolve(exact);
        }

        List<Asset> wholeHost = distinctAssets(candidates.stream()
                .filter(ip -> ip.port == null).toList());
        if (!wholeHost.isEmpty()) return resolve(wholeHost);

        return notFound();
    }

    private static Match resolve(List<Asset> assets) {
        return assets.size() == 1
                ? new Match(NessusFinding.AssetResolution.MATCHED, assets.get(0))
                : new Match(NessusFinding.AssetResolution.AMBIGUOUS, null);
    }

    private static Match notFound() {
        return new Match(NessusFinding.AssetResolution.NOT_FOUND, null);
    }

    private static List<Asset> distinctAssets(List<AssetIp> rows) {
        return rows.stream().map(ip -> ip.asset).filter(Objects::nonNull).distinct().toList();
    }
}
