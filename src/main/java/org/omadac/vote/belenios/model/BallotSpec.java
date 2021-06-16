package org.omadac.vote.belenios.model;

import java.util.List;

import org.immutables.value.Value.Immutable;

@Immutable
@ValueStyle
public interface BallotSpec {

    List<Answer> answers();

    String electionHash();

    String electionUuid();

    Signature signature();

}
