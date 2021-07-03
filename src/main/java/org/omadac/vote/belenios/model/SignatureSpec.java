package org.omadac.vote.belenios.model;

import java.math.BigInteger;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize
public interface SignatureSpec {

    @JsonProperty("public_key")
    BigInteger publicKey();

    BigInteger challenge();

    BigInteger response();
}
