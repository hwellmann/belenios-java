package org.omadac.vote.belenios.algo;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import org.omadac.vote.belenios.algo.Groups;
import org.omadac.vote.belenios.model.Group;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class GroupSerializationTest {

    @Test
    public void shouldSerialize() throws JsonProcessingException {
        var group = Groups.HOMOMORPHIC;
        var mapper = new ObjectMapper();

        mapper.configOverride(BigInteger.class)
            .setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));

        var json = mapper.writeValueAsString(group);
        assertThat(json).startsWith("{\"g\":\"2402");

        var group2 = mapper.readValue(json, Group.class);
        assertThat(group2).isEqualTo(group);
    }
}
