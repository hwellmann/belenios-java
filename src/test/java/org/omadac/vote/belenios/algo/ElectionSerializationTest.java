package org.omadac.vote.belenios.algo;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;
import org.omadac.vote.belenios.model.Election;

public class ElectionSerializationTest {

    @Test
    public void shouldReproduceExactJsonString() throws IOException {
        var json = Files.readString(Paths.get("src/test/resources/election01/election.json"));
        var election = JsonMapper.INSTANCE.readValue(json, Election.class);

        assertThat(JsonMapper.INSTANCE.writeValueAsString(election)).isEqualTo(json);
    }
}
