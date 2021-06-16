package org.omadac.vote.belenios.model;

import java.util.List;

import org.immutables.value.Value.Immutable;

@Immutable
@ValueStyle
public interface AnswerSpec {

    List<Ciphertext> choices();

    List<List<Proof>> individualProofs();

    List<Proof> overallProof();

    // @Nullable
    List<Proof> blankProof();
}
