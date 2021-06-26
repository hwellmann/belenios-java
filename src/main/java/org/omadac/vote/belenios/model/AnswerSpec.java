package org.omadac.vote.belenios.model;

import java.util.List;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize(builder = Answer.Builder.class)
public interface AnswerSpec {

    List<Ciphertext> choices();

    @JsonProperty("individual_proofs")
    List<List<Proof>> individualProofs();

    @JsonProperty("overall_proof")
    List<Proof> overallProof();

    // @Nullable
    @JsonProperty("blank_proof")
    List<Proof> blankProof();
}
