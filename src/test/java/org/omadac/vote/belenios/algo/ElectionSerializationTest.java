package org.omadac.vote.belenios.algo;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;
import org.omadac.vote.belenios.model.Election;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ElectionSerializationTest {

    @Test
    public void shouldReproduceExactJsonString() throws IOException {
        var mapper = new ObjectMapper();

        mapper.configOverride(BigInteger.class)
            .setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));

        var json = Files.readString(Paths.get("src/test/resources/election01/election.json"));
        var election = mapper.readValue(json, Election.class);

        assertThat(mapper.writeValueAsString(election)).isEqualTo(json);
    }
}
