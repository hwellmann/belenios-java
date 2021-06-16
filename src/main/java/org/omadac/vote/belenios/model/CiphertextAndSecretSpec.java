package org.omadac.vote.belenios.model;

import java.math.BigInteger;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize(builder = CiphertextAndSecret.Builder.class)
public interface CiphertextAndSecretSpec {

    BigInteger alpha();

    BigInteger beta();

    BigInteger r();

    default Ciphertext ciphertext() {
        return Ciphertext.builder().alpha(alpha()).beta(beta()).build();
    }
}
