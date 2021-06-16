package org.omadac.vote.belenios.model;

import java.util.List;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.annotation.JsonProperty;

@Immutable
@ValueStyle
public interface ResultSpec {

    @JsonProperty("num_tallied")
    int numTallied();

    @JsonProperty("encrypted_tally")
    List<List<Ciphertext>> encryptedTally();

    @JsonProperty("partial_decryptions")
    List<PartialDecryption> partialDecryptions();

    List<List<Integer>> result();
}
