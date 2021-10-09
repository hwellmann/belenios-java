import { Answer, Credentials, Election } from './Model';
import { toSecretKey } from './GenCredentials';
import { random } from './GenRandomInteger';

export function createSignature(answers: Answer[], credentials: Credentials, election: Election) {
    const group = election.public_key.group;
    const secretKey = toSecretKey(credentials.privateCred, election.uuid, group.q); 
    const w = random(group.q);
    const a = group.g.modPow(w, group.p);
    const text = answers.map(a => a.choices)
    return null;
}

