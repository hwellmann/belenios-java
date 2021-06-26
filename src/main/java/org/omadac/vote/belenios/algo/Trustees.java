package org.omadac.vote.belenios.algo;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import org.omadac.vote.belenios.model.TrusteePublicKey;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;

public class Trustees {

    private static TrusteePublicKey toPublicKeys(List<Object> trustee) {
        if ("Single".equals(trustee.get(0))) {
            try {
                String json = JsonMapper.INSTANCE.writeValueAsString(trustee.get(1));
                return JsonMapper.INSTANCE.readValue(json, TrusteePublicKey.class);
            } catch (JsonProcessingException exc) {
                throw new IllegalArgumentException(exc);
            }
        }
        return null;
    }

    public static List<TrusteePublicKey> readTrustees(File file) {
        try {
            List<List<Object>> trustees = JsonMapper.INSTANCE.readValue(file, new TypeReference<>() {});
            return trustees.stream()
                .map(Trustees::toPublicKeys)
                .collect(Collectors.toList());
        } catch (IOException exc) {
            throw new IllegalArgumentException(exc);
        }
    }
}
