package org.omadac.vote.belenios.model;

import java.util.List;

import org.immutables.value.Value.Immutable;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@Immutable
@ValueStyle
@JsonDeserialize(builder = Election.Builder.class)
public interface ElectionSpec {

    String description();

    String name();

    @JsonProperty("public_key")
    WrappedPublicKey publicKey();

    List<Question> questions();

    String uuid();

    String administrator();

    @JsonProperty("credential_authority")
    String credentialAuthority();
}
