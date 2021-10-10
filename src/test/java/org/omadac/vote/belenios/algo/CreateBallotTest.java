package org.omadac.vote.belenios.algo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.omadac.vote.belenios.algo.CreateBallot.createBallot;
import static org.omadac.vote.belenios.algo.VerifyBallot.verifyBallot;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Credentials;
import org.omadac.vote.belenios.model.Election;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class CreateBallotTest {

    private String secretCred = "qzw-2ie-y6H-TSD-bGK";
    private BigInteger publicCred = new BigInteger(
        "10029862746834958143319323111454409387590534954793044404822945369994744260442089371115262190203934804675786564182282779251355216210946054924334240642428855729296421330257013472191135818728983762408033399214480787226293273548568201935296926228677329878383724409798063156434251931695634528137005735620183893704077873291267277770009834510370291772787286847855329543445255587222293360124381540329014428549828158233880255987012301417548047705955061799010400287887972369638914661074191768045129220621711681227211225478992052827599600084274797905069932956260221255187797967125498373990647751773001873864960847565145552988003");
    private Credentials credentials = Credentials.builder().privateCred(secretCred).publicCred(publicCred).build();

    @Test
    public void shouldCreateBallot() throws Exception {
        var election = readElection();

        var ballot = createBallot(election, credentials, List.of(List.of(0, 1, 0)));
        assertThat(verifyBallot(ballot, election)).isTrue();
    }

    private Election readElection() throws IOException, JsonProcessingException, JsonMappingException {
        var mapper = new ObjectMapper();

        mapper.configOverride(BigInteger.class)
            .setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));

        var json = Files.readString(Paths.get("src/test/resources/election01/election.json"));
        var election = mapper.readValue(json, Election.class);
        return election;
    }

    private Ballot readBallot() throws IOException, JsonProcessingException, JsonMappingException {
        var mapper = new ObjectMapper();

        mapper.configOverride(BigInteger.class)
            .setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));

        var json = Files.readString(Paths.get("src/test/resources/election01/ballot.json"));
        var election = mapper.readValue(json, Ballot.class);
        return election;
    }

    @Test
    public void shouldCreateBlankBallot() throws Exception {
        var election = readElection();

        var ballot = createBallot(election, credentials, List.of(List.of(1, 0, 0)));
        assertThat(verifyBallot(ballot, election)).isTrue();
    }

    @Test
    public void shouldCreateElectionHash() throws Exception {
        var election = readElection();
        var hash = CreateBallot.createElectionHash(election);
        System.out.println(hash);
    }

    @Test
    public void shouldVerifyBallot() throws Exception {
        var election = readElection();

        var ballot = readBallot();
        assertThat(verifyBallot(ballot, election)).isTrue();
    }
}
