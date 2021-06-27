package org.omadac.vote.belenios.model;

import java.math.BigInteger;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import org.immutables.value.Value.Immutable;

@Immutable
@ValueStyle
@JsonDeserialize(builder = PartialDecryption.Builder.class)
public interface PartialDecryptionSpec {

    @JsonProperty("decryption_factors")
    List<List<BigInteger>> decryptionFactors();

    @JsonProperty("decryption_proofs")
    List<List<Proof>> decryptionProofs();
}
