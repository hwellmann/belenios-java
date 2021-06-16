package org.omadac.vote.belenios.model;

import java.math.BigInteger;

import org.immutables.value.Value.Immutable;

@Immutable
@ValueStyle
public interface TrusteePublicKeySpec {

    String id();

    Proof pok();

    BigInteger publicKey();
}
