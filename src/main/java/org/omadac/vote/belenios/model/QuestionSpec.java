package org.omadac.vote.belenios.model;

import java.util.List;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize
public interface QuestionSpec {

    List<String> answers();

    Boolean blank();

    int min();

    int max();

    String question();

    default boolean blankAnswerAllowed() {
        return blank() != null && blank();
    }
}
