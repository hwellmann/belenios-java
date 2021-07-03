package org.omadac.vote.belenios.model;

import java.math.BigInteger;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import org.immutables.value.Value.Immutable;

@Immutable
@ValueStyle
@JsonDeserialize
public interface TrusteeKeyPairSpec {

    TrusteePublicKey trusteePublicKey();

    String id();

    BigInteger privateKey();
}
