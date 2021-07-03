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

    default CiphertextAndSecret combine(CiphertextAndSecret other, BigInteger p) {
        var alpha = alpha().multiply(other.alpha()).mod(p);
        var beta = beta().multiply(other.beta()).mod(p);
        var r = r().add(other.r()).mod(p);
        return CiphertextAndSecret.builder().alpha(alpha).beta(beta).r(r).build();
    }
}
