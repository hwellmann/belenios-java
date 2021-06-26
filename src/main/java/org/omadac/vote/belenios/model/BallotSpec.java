package org.omadac.vote.belenios.model;

import java.util.List;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize(builder = Ballot.Builder.class)
public interface BallotSpec {

    List<Answer> answers();

    String electionHash();

    String electionUuid();

    Signature signature();

}
