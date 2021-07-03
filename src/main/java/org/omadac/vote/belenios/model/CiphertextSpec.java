package org.omadac.vote.belenios.model;

import java.math.BigInteger;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize
public interface CiphertextSpec {

    static Ciphertext NEUTRAL = Ciphertext.builder().alpha(BigInteger.ONE).beta(BigInteger.ONE).build();

    BigInteger alpha();

    BigInteger beta();

    default Ciphertext combine(Ciphertext other, BigInteger p) {
        var alpha = alpha().multiply(other.alpha()).mod(p);
        var beta = beta().multiply(other.beta()).mod(p);
        return Ciphertext.builder().alpha(alpha).beta(beta).build();
    }
}
