package org.omadac.vote.belenios.model;

import java.math.BigInteger;
import java.util.List;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.annotation.JsonProperty;

@Immutable
@ValueStyle
public interface PartialDecryptionSpec {

    @JsonProperty("decryption_factors")
    List<List<BigInteger>> decryptionFactors();

    @JsonProperty("decryption_proofs")
    List<List<Proof>> decryptionProofs();
}
