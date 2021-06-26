package org.omadac.vote.belenios.cli;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.Callable;

import org.omadac.vote.belenios.algo.CreateElectionResult;
import org.omadac.vote.belenios.algo.CreateEncryptedTally;
import org.omadac.vote.belenios.algo.JsonMapper;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Ciphertext;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.PartialDecryption;
import org.omadac.vote.belenios.model.Result;

import picocli.CommandLine.Command;

@Command(name = "validate", mixinStandardHelpOptions = true, description = "This command reads partial decryptions done by trustees from file "
    + "partial_decryptions.jsons, checks them, combines them into the final "
    + "tally and prints the result to standard output.\n\n"
    + "The result structure contains partial decryptions itself, so "
    + "partial_decryptions.jsons can be discarded afterwards.\n\n")
public class Validate implements Callable<Integer> {

    private PartialDecryption toPartialDescription(String json) {
        try {
            return JsonMapper.INSTANCE.readValue(json, PartialDecryption.class);
        } catch (IOException exc) {
            throw new IllegalArgumentException(exc);
        }
    }

    private Ballot toBallot(String line) {
        try {
            return JsonMapper.INSTANCE.readValue(line, Ballot.class);
        } catch (IOException exc) {
            throw new IllegalArgumentException("Cannot parse ballot", exc);
        }
    }

    @Override
    public Integer call() throws Exception {
        var electionFile = new File("election.json");
        if (!electionFile.exists()) {
            System.err.println("Election file " + electionFile + " does not exist");
            return 1;
        }
        var trusteesFile = new File("trustees.json");
        if (!trusteesFile.exists()) {
            System.err.println("Trustees file " + electionFile + " does not exist");
            return 1;
        }
        var ballotsFile = new File("ballots.jsons");
        if (!ballotsFile.exists()) {
            System.err.println("Ballots file " + ballotsFile + " does not exist");
            return 1;
        }
        var partialDecryptionsFile = new File("partial_decryptions.jsons");
        if (!partialDecryptionsFile.exists()) {
            System.err.println("File " + partialDecryptionsFile + " does not exist");
            return 1;
        }

        var election = JsonMapper.INSTANCE.readValue(electionFile, Election.class);
        List<PartialDecryption> partialDecryptions = Files.lines(partialDecryptionsFile.toPath())
            .map(this::toPartialDescription)
            .collect(toList());

        List<Ballot> ballots = Files.lines(ballotsFile.toPath(), UTF_8).map(this::toBallot)
            .collect(toList());
        List<List<Ciphertext>> encryptedTally = CreateEncryptedTally.tally(election, ballots.stream());

        Result result = CreateElectionResult.createResult(election, ballots.size(), encryptedTally, partialDecryptions);
        JsonMapper.INSTANCE.writeValue(new File("result.json"), result);
        return 0;
    }
}
