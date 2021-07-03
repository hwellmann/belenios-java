package org.omadac.vote.belenios.model;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize
public interface SingleTrusteeSpec {

    String kind();

    TrusteePublicKey trustee();
}
