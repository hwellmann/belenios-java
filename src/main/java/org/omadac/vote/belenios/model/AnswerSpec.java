package org.omadac.vote.belenios.model;

import java.util.List;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize(builder = Answer.Builder.class)
public interface AnswerSpec {

    List<Ciphertext> choices();

    List<List<Proof>> individualProofs();

    List<Proof> overallProof();

    // @Nullable
    List<Proof> blankProof();
}
