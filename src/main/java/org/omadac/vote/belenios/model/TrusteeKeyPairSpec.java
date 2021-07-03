package org.omadac.vote.belenios.model;

import java.math.BigInteger;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize(builder = TrusteeKeyPair.Builder.class)
public interface TrusteeKeyPairSpec {

    TrusteePublicKey trusteePublicKey();

    String id();

    BigInteger privateKey();
}
