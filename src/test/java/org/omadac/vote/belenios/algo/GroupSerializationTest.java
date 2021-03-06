package org.omadac.vote.belenios.algo;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.core.JsonProcessingException;

import org.junit.jupiter.api.Test;
import org.omadac.vote.belenios.model.Group;

public class GroupSerializationTest {

    @Test
    public void shouldSerialize() throws JsonProcessingException {
        var group = Groups.HOMOMORPHIC;
        var json = JsonMapper.INSTANCE.writeValueAsString(group);
        assertThat(json).startsWith("{\"g\":\"2402");

        var group2 = JsonMapper.INSTANCE.readValue(json, Group.class);
        assertThat(group2).isEqualTo(group);
    }
}
