package org.omadac.vote.belenios.model;

import java.math.BigInteger;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize(builder = TrusteePublicKey.Builder.class)
public interface TrusteePublicKeySpec {

    Proof pok();

    @JsonProperty("public_key")
    BigInteger publicKey();
}
