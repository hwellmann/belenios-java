package org.omadac.vote.belenios.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import org.immutables.value.Value.Immutable;

@Immutable
@ValueStyle
@JsonDeserialize
public interface AnswerSpec {

    List<Ciphertext> choices();

    @JsonProperty("individual_proofs")
    List<List<Proof>> individualProofs();

    @JsonProperty("overall_proof")
    List<Proof> overallProof();

    @JsonProperty("blank_proof")
    @JsonInclude(Include.NON_EMPTY)
    List<Proof> blankProof();
}
