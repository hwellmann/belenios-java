package org.omadac.vote.belenios.cli;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.Callable;

import org.omadac.vote.belenios.algo.CreateBallot;
import org.omadac.vote.belenios.algo.GenCredentials;
import org.omadac.vote.belenios.algo.JsonMapper;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Credentials;
import org.omadac.vote.belenios.model.Election;

import com.fasterxml.jackson.core.type.TypeReference;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "vote", mixinStandardHelpOptions = true, description = "This command creates a ballot and prints it on standard output.\n\n")
public class Vote implements Callable<Integer> {

    @Option(names = {"--ballot"}, description = "Read ballot choices from file BALLOT", required = true)
    private File ballot;

    @Option(names = {"--privcred"}, description = "Read private credential from file PRIV_CRED", required = true)
    private File privcred;

    @Override
    public Integer call() throws Exception {
        if (!ballot.exists()) {
            System.err.println("Ballot file " + ballot + " does not exist");
            return 1;
        }
        if (!privcred.exists()) {
            System.err.println("Credential file " + privcred + " does not exist");
            return 1;
        }
        List<List<Integer>> rawVotes = JsonMapper.INSTANCE.readValue(ballot, new TypeReference<>() {});
        String privcred = Files.readString(ballot.toPath(), StandardCharsets.UTF_8).trim();
        Election election = JsonMapper.INSTANCE.readValue(new File("election.json"), Election.class);
        BigInteger pubCred = GenCredentials.derive(privcred, election.uuid(), election.publicKey().group());

        Credentials credentials = Credentials.builder().privateCred(privcred).publicCred(pubCred).build();

        Ballot ballot = CreateBallot.createBallot(election, credentials, rawVotes);
        String json = JsonMapper.INSTANCE.writeValueAsString(ballot);
        System.out.println(json);
        return 0;
    }
}