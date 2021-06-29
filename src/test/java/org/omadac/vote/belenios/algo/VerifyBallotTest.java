package org.omadac.vote.belenios.algo;

import static java.util.stream.Collectors.toList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.omadac.vote.belenios.algo.VerifyBallot.verifyBallot;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

import org.junit.jupiter.api.Test;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Election;

public class VerifyBallotTest {

    private static final String DIR = "src/test/resources/4BmyrdywTpwJry";

    @Test
    public void shouldVerifyBallot() throws Exception {
        var election = readElection();
        var ballots = readBallots();
        for (Ballot ballot: ballots) {
            assertThat(verifyBallot(ballot, election)).isTrue();
        }
    }

    private Election readElection()
        throws IOException, JsonProcessingException, JsonMappingException {
        var json = Files.readString(Paths.get(DIR, "election.json"));
        var election = JsonMapper.INSTANCE.readValue(json, Election.class);
        return election;
    }

    private List<Ballot> readBallots() throws IOException {
        return Files.lines(Paths.get(DIR, "ballots.jsons"), StandardCharsets.UTF_8)
            .map(json -> JsonMapper.fromJson(json, Ballot.class))
            .collect(toList());
    }
}
