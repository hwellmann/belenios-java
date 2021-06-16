package org.omadac.vote.belenios.model;

import java.math.BigInteger;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize(builder = Credentials.Builder.class)
public interface CredentialsSpec {

    String privateCred();

    BigInteger publicCred();
}
