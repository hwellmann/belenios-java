package org.omadac.vote.belenios.model;

import java.math.BigInteger;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize(builder = WrappedPublicKey.Builder.class)
public interface WrappedPublicKeySpec {

    Group group();

    BigInteger y();
}
