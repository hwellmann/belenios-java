package org.omadac.vote.belenios.model;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize(builder = WeightedBallot.Builder.class)
public interface WeightedBallotSpec {

    int weight();

    Ballot ballot();
}
