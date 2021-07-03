package org.omadac.vote.belenios.model;

import java.util.List;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize
public interface BallotSpec {

    List<Answer> answers();

    @JsonProperty("election_hash")
    String electionHash();

    @JsonProperty("election_uuid")
    String electionUuid();

    Signature signature();

}
