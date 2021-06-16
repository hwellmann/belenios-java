package org.omadac.vote.belenios.model;

import java.math.BigInteger;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize(builder = Ciphertext.Builder.class)
public interface CiphertextSpec {

    static Ciphertext NEUTRAL = Ciphertext.builder().alpha(BigInteger.ONE).beta(BigInteger.ONE).build();

    BigInteger alpha();

    BigInteger beta();
}
