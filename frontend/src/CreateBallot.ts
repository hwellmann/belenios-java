import { addCts, Answer, Ballot, Ciphertext, CiphertextAndSecret, Credentials, Election, Proof, Question, replaceElection, WrappedPublicKey } from './Model';
import { toSecretKey } from './GenCredentials';
import { random } from './GenRandomInteger';
import { checksum } from './ModularChecksum';
import * as sjcl from 'sjcl';
import { BigInteger } from 'jsbn';

export function createSignature(answers: Answer[], credentials: Credentials, election: Election) {
    const group = election.public_key.group;
    const secretKey = toSecretKey(credentials.privateCred, election.uuid, group.q); 
    const w = random(group.q);
    const a = group.g.modPow(w, group.p);
    const text = answers.flatMap(answer => answer.choices)
        .map(c => c.alpha.toString() + ',' + c.beta.toString())
        .join(','); 
    const message = `sig|${credentials.publicCred}|${a}|${text}`;
    const challenge = checksum(message, group.q);
    const response = w.subtract(secretKey.multiply(challenge)).mod(group.q);    
    return { public_key: credentials.publicCred, challenge, response };
}

export function createElectionHash(election: Election) {
    const json = JSON.stringify(election, replaceElection);
    const hash = sjcl.hash.sha256.hash(json);
    return sjcl.codec.base64.fromBits(hash).replace('=', '');    
}

export function createBallot(election: Election, credentials: Credentials, rawVotes: number[][]): Ballot {
    const answers = [];
    for (var i = 0; i < rawVotes.length; i++) {
        const question = election.questions[i];
        const rawVote = rawVotes[i];
        const answer = createAnswer(election.public_key, credentials.publicCred, question, rawVote);
        answers.push(answer);
    }
    const signature = createSignature(answers, credentials, election);
    return {
        answers,
        election_uuid: election.uuid,
        election_hash: createElectionHash(election),
        signature
    };
}

function createAnswer(publicKey: WrappedPublicKey, publicCred: BigInteger, question: Question, rawVote: number[]): Answer {
    const choicesAndProofs = rawVote.map(vote => createCiphertext(publicKey, publicCred, vote));
    const choicesAndSecrets = choicesAndProofs.map(cp => cp[0]);
    const choices = choicesAndSecrets.map(cs => { return {alpha: cs.alpha, beta: cs.beta } });
    const proofs = choicesAndProofs.map(cp => cp[1]);

    const ct0 = choicesAndSecrets[0];
    const ctSigma = choicesAndSecrets.slice(1)
        .reduce((left, right) => addCts(left, right, publicKey.group.p));

    const prefix = [publicKey.group.g, publicKey.y, ct0.alpha, ct0.beta, ctSigma.alpha, ctSigma.beta]
        .map(bi => bi.toString())
        .join(',');

    if (question.blank) {
        return { choices, 
            individual_proofs: proofs, 
            blank_proof: createBlankProof(publicKey, publicCred, ct0, ctSigma, rawVote[0], prefix), 
            overall_proof: createOverallProof(publicKey, publicCred, ct0, ctSigma, rawVote[0], prefix)
        };
    }    
    
    const choice = rawVote.reduce((left, right) => left + right);
    return { choices, 
        individual_proofs: proofs, 
        overall_proof: createIntervalProof(publicKey, publicCred, ctSigma, choice, question.min, question.max)
    };
}    


function createCiphertext(publicKey: WrappedPublicKey, publicCred: BigInteger, rawVote: number)
    : [CiphertextAndSecret, Proof[]] {
    
    const group = publicKey.group;
    const r = random(group.q);
    const alpha = group.g.modPow(r, group.p);
    const beta = publicKey.y.modPow(r, group.p)
        .multiply(group.g.modPow(new BigInteger(rawVote.toString()), group.p))
        .mod(group.p);
    const ct = { alpha, beta, r };
    const proofs = createIntervalProof(publicKey, publicCred, ct, rawVote, 0, 1);    
    return [ct, proofs];
}

function createIntervalProof(publicKey: WrappedPublicKey, publicCred: BigInteger, 
    ct: CiphertextAndSecret, choice: number, min: number, max: number): Proof[] {
    const proofs: Proof[] = [];
    const abs: Ciphertext[] = [];
    const group = publicKey.group;
    for (var j: number = min; j <= max; j++) {
        if (j === choice) {
            const proof = { challenge: BigInteger.ZERO, response: BigInteger.ZERO };
            proofs.push(proof);
            
            const ab = { alpha: BigInteger.ZERO, beta: BigInteger.ZERO };
            abs.push(ab);
        } else {
            const challenge = random(group.q);
            const response = random(group.q);
            const proof = { challenge, response };
            proofs.push(proof);

            const aNum = group.g.modPow(response, group.p);
            const aDenom = ct.alpha.modPow(challenge, group.p);
            const a = aNum.multiply(aDenom.modInverse(group.p)).mod(group.p);

            const bNum = publicKey.y.modPow(response, group.p);
            const bDenom = ct.beta.multiply(group.g.modInverse(group.p).modPow(new BigInteger(j.toString()), group.p))
                .modPow(challenge, group.p);
            const b = bNum.multiply(bDenom.modInverse(group.p)).mod(group.p);
            abs.push({alpha: a, beta: b});    
        }
    }

    const i = choice - min;
    const w = random(group.q);
    const ai = group.g.modPow(w, group.p);
    const bi = publicKey.y.modPow(w, group.p);
    abs[i] = { alpha: ai, beta: bi };

    const suffix = abs.flatMap(ab => [ab.alpha, ab.beta])
        .map(bi => bi.toString())
        .join(',');
    let message = `prove|${publicCred.toString()}|${ct.alpha.toString()},${ct.beta.toString()}|${suffix}`;
    const cs = checksum(message, group.q);

    const challengeSum = proofs.map(p => p.challenge).reduce((left, right) => left.add(right));
    const challengei = cs.subtract(challengeSum).mod(group.q);
    const responsei = challengei.multiply(ct.r).add(w).mod(group.q);
    proofs[i] = { challenge: challengei, response: responsei };

    return proofs;
}


function createBlankProof(publicKey: WrappedPublicKey, publicCred: BigInteger, 
    ct0: CiphertextAndSecret, ctSigma: CiphertextAndSecret, isBlank: number, prefix: string): Proof[] {
    const group = publicKey.group;
    if (isBlank === 0) {
        const challengeSigma = random(group.q);
        const responseSigma = random(group.q);
        
        const aSigma = group.g.modPow(responseSigma, group.p)
            .multiply(ctSigma.alpha.modPow(challengeSigma, group.p))
            .mod(group.p);
        const bSigma = publicKey.y.modPow(responseSigma, group.p)
            .multiply(ctSigma.beta.modPow(challengeSigma, group.p))
            .mod(group.p);

        const w = random(group.q);
        const a0 = group.g.modPow(w, group.p);
        const b0 = publicKey.y.modPow(w, group.p);
        
        const message = `bproof0|${publicCred}|${prefix}|${a0},${b0},${aSigma},${bSigma}`;
        const cs = checksum(message, group.q);

        const challenge0 = cs.subtract(challengeSigma).mod(group.q);
        const response0 = w.subtract(ct0.r.multiply(challenge0)).mod(group.q);
        const proof0 = { challenge: challenge0, response: response0 };
        const proofSigma = { challenge: challengeSigma, response: responseSigma };
        return [ proof0, proofSigma ];
    } else {
        const challenge0 = random(group.q);
        const response0 = random(group.q);
        
        const a0 = group.g.modPow(response0, group.p)
            .multiply(ct0.alpha.modPow(challenge0, group.p)).mod(group.p);
        const b0 = publicKey.y.modPow(response0, group.p)
            .multiply(ct0.beta.modPow(challenge0, group.p))
            .mod(group.p);

        const w = random(group.q);
        const aSigma = group.g.modPow(w, group.p);
        const bSigma = publicKey.y.modPow(w, group.p);
        
        const message = `bproof0|${publicCred}|${prefix}|${a0},${b0},${aSigma},${bSigma}`;
        const cs = checksum(message, group.q);

        const challengeSigma = cs.subtract(challenge0).mod(group.q);
        const responseSigma = w.subtract(ctSigma.r.multiply(challengeSigma)).mod(group.q);
        const proof0 = { challenge: challenge0, response: response0 };
        const proofSigma = { challenge: challengeSigma, response: responseSigma };
        return [ proof0, proofSigma ];
    }
}


function createOverallProof(publicKey: WrappedPublicKey, publicCred: BigInteger, 
    ct0: CiphertextAndSecret, ctSigma: CiphertextAndSecret, isBlank: number, prefix: string): Proof[] {
    const group = publicKey.group;
    if (isBlank === 0) {
        const challenge0 = random(group.q);
        const response0 = random(group.q);
        
        const a0 = group.g.modPow(response0, group.p)
            .multiply(ct0.alpha.modPow(challenge0, group.p)).mod(group.p);
        const b0 = publicKey.y.modPow(response0, group.p)
            .multiply(ct0.beta.multiply(group.g.modInverse(group.p))
                .modPow(challenge0, group.p))
            .mod(group.p);

        const w = random(group.q);
        const a1 = group.g.modPow(w, group.p);
        const b1 = publicKey.y.modPow(w, group.p);
        
        const message = `bproof1|${publicCred}|${prefix}|${a0},${b0},${a1},${b1}`;
        const cs = checksum(message, group.q);

        const challenge1 = cs.subtract(challenge0).mod(group.q);
        const response1 = w.subtract(ctSigma.r.multiply(challenge1)).mod(group.q);
        const proof0 = { challenge: challenge0, response: response0 };
        const proof1 = { challenge: challenge1, response: response1 };
        return [ proof0, proof1 ];
    } else {
        const challenge1 = random(group.q);
        const response1 = random(group.q);
        
        const a1 = group.g.modPow(response1, group.p)
            .multiply(ctSigma.alpha.modPow(challenge1, group.p)).mod(group.p);
        const b1 = publicKey.y.modPow(response1, group.p)
            .multiply(ctSigma.beta.multiply(group.g.modInverse(group.p))
                .modPow(challenge1, group.p))
            .mod(group.p);

        const w = random(group.q);
        const a0 = group.g.modPow(w, group.p);
        const b0 = publicKey.y.modPow(w, group.p);
        
        const message = `bproof1|${publicCred}|${prefix}|${a0},${b0},${a1},${b1}`;
        const cs = checksum(message, group.q);

        const challenge0 = cs.subtract(challenge1).mod(group.q);
        const response0 = w.subtract(ct0.r.multiply(challenge0)).mod(group.q);
        const proof0 = { challenge: challenge0, response: response0 };
        const proof1 = { challenge: challenge1, response: response1 };
        return [ proof0, proof1 ];
    }
}

